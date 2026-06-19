//! See [`MojangClient`].

use std::{sync::Arc, time::Duration};

use anyhow::{Context, bail};
use bevy::prelude::*;
use serde_json::Value;
use tokio::{
    sync::Semaphore,
    time::{MissedTickBehavior, interval},
};
use tracing::warn;
use uuid::Uuid;

use crate::AsyncRuntime;

/// The API provider to use for Minecraft profile lookups
#[derive(Clone, Copy)]
pub struct ApiProvider {
    username_base_url: &'static str,
    uuid_base_url: &'static str,
    max_requests: usize,
    interval: Duration,
}

impl ApiProvider {
    /// The matdoes.dev API mirror provider with higher rate limits
    pub const MAT_DOES_DEV: Self = Self {
        username_base_url: "https://mowojang.matdoes.dev/users/profiles/minecraft",
        uuid_base_url: "https://mowojang.matdoes.dev/session/minecraft/profile",
        max_requests: 10_000,
        interval: Duration::from_secs(1),
    };
    /// The official Mojang API provider
    pub const MOJANG: Self = Self {
        username_base_url: "https://api.mojang.com/users/profiles/minecraft",
        uuid_base_url: "https://sessionserver.mojang.com/session/minecraft/profile",
        max_requests: 600,
        interval: Duration::from_mins(10),
    };

    fn username_url(&self, username: &str) -> String {
        format!("{}/{username}", self.username_base_url)
    }

    fn uuid_url(&self, uuid: &Uuid) -> String {
        format!("{}/{uuid}?unsigned=false", self.uuid_base_url)
    }

    const fn max_requests(&self) -> usize {
        self.max_requests
    }

    const fn interval(&self) -> Duration {
        self.interval
    }
}

/// A client to interface with the Minecraft profile API.
///
/// Can use either the official Mojang API or [matdoes/mowojang](https://matdoes.dev/minecraft-uuids) as a data source.
/// This does not include caching, this should be done separately probably using [`crate::storage::LocalDb`].
#[derive(Resource, Clone)]
pub struct MojangClient {
    req: reqwest::Client,
    rate_limit: Arc<Semaphore>,
    provider: ApiProvider,
}

impl MojangClient {
    #[must_use]
    pub fn new(runtime: &AsyncRuntime, provider: ApiProvider) -> Self {
        let rate_limit = Arc::new(Semaphore::new(provider.max_requests()));
        let interval_duration = provider.interval();

        runtime.spawn({
            let rate_limit = Arc::downgrade(&rate_limit);
            let max_requests = provider.max_requests();
            async move {
                let mut interval = interval(interval_duration);
                interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

                loop {
                    interval.tick().await;

                    let Some(rate_limit) = rate_limit.upgrade() else {
                        return;
                    };

                    let available = rate_limit.available_permits();
                    rate_limit.add_permits(max_requests - available);
                }
            }
        });

        Self {
            req: reqwest::Client::new(),
            rate_limit,
            provider,
        }
    }

    /// Gets a player's UUID from their username.
    pub async fn get_uuid(&self, username: &str) -> anyhow::Result<Uuid> {
        let url = self.provider.username_url(username);
        let json_object = self.response_raw(&url).await?;

        uuid_from_profile_response(&json_object)
    }

    /// Gets a player's username from their UUID.
    pub async fn get_username(&self, uuid: Uuid) -> anyhow::Result<String> {
        let url = self.provider.uuid_url(&uuid);
        let json_object = self.response_raw(&url).await?;

        username_from_profile_response(&json_object)
    }

    /// Gets player data from their UUID.
    pub async fn data_from_uuid(&self, uuid: &Uuid) -> anyhow::Result<Value> {
        let url = self.provider.uuid_url(uuid);
        self.response_raw(&url).await
    }

    /// Gets player data from their username.
    pub async fn data_from_username(&self, username: &str) -> anyhow::Result<Value> {
        let url = self.provider.username_url(username);
        self.response_raw(&url).await
    }

    async fn response_raw(&self, url: &str) -> anyhow::Result<Value> {
        self.rate_limit
            .acquire()
            .await
            .expect("semaphore is never closed")
            .forget();

        if self.rate_limit.available_permits() == 0 {
            warn!(
                "rate limiting will be applied: {} requests have been sent in the past {:?} \
                 interval",
                self.provider.max_requests(),
                self.provider.interval()
            );
        }

        let response = self.req.get(url).send().await?;

        if response.status().is_success() {
            let body = response.text().await?;
            let json_object = serde_json::from_str::<Value>(&body)
                .with_context(|| format!("failed to parse json from response: {body:?}"))?;

            if let Some(error) = json_object.get("error") {
                bail!("API Error: {}", error.as_str().unwrap_or("Unknown error"));
            }
            Ok(json_object)
        } else {
            bail!("Failed to retrieve data from API");
        }
    }
}

fn uuid_from_profile_response(json_object: &Value) -> anyhow::Result<Uuid> {
    let id = json_object
        .get("id")
        .context("no id in json")?
        .as_str()
        .context("id is not a string")?;

    Uuid::parse_str(id).map_err(Into::into)
}

fn username_from_profile_response(json_object: &Value) -> anyhow::Result<String> {
    json_object
        .get("name")
        .context("no name in json")?
        .as_str()
        .map(String::from)
        .context("Username not found")
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "these are tests")]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use super::{ApiProvider, username_from_profile_response, uuid_from_profile_response};

    const PROFILE_UUID_HYPHENATED: &str = "86271406-1188-44a5-8496-7af10c906204";
    const PROFILE_UUID_COMPACT: &str = "86271406118844a584967af10c906204";
    const PROFILE_NAME: &str = "Emerald_Explorer";

    fn profile_json() -> serde_json::Value {
        json!({
            "id": PROFILE_UUID_COMPACT,
            "name": PROFILE_NAME,
            "profileActions": []
        })
    }

    #[test]
    fn uuid_from_profile_response_accepts_compact_uuid() {
        let uuid = uuid_from_profile_response(&profile_json()).unwrap();
        let expected = Uuid::parse_str(PROFILE_UUID_HYPHENATED).unwrap();

        assert_eq!(uuid, expected);
    }

    #[test]
    fn uuid_from_profile_response_rejects_missing_id() {
        let err = uuid_from_profile_response(&json!({ "name": PROFILE_NAME })).unwrap_err();

        assert!(err.to_string().contains("no id"));
    }

    #[test]
    fn username_from_profile_response_accepts_name() {
        let username = username_from_profile_response(&profile_json()).unwrap();

        assert_eq!(username, PROFILE_NAME);
    }

    #[test]
    fn username_from_profile_response_rejects_non_string_name() {
        let err = username_from_profile_response(&json!({ "name": true })).unwrap_err();

        assert!(err.to_string().contains("Username not found"));
    }

    #[test]
    fn api_provider_formats_username_url() {
        let url = ApiProvider::MAT_DOES_DEV.username_url(PROFILE_NAME);

        assert_eq!(
            url,
            "https://mowojang.matdoes.dev/users/profiles/minecraft/Emerald_Explorer"
        );
    }

    #[test]
    fn api_provider_formats_signed_uuid_url() {
        let uuid = Uuid::parse_str(PROFILE_UUID_HYPHENATED).unwrap();
        let url = ApiProvider::MAT_DOES_DEV.uuid_url(&uuid);

        assert_eq!(
            url,
            "https://mowojang.matdoes.dev/session/minecraft/profile/86271406-1188-44a5-8496-7af10c906204?unsigned=false"
        );
    }
}
