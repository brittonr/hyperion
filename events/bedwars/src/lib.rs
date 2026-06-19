#![feature(allocator_api)]
#![feature(let_chains)]
#![feature(stmt_expr_attributes)]
#![feature(exact_size_is_empty)]

use std::net::SocketAddr;

use bevy::prelude::*;
use hyperion::{Crypto, HyperionCore, ProxyBind, simulation::packet_state, spatial::Spatial};
use hyperion_proxy_module::SetProxyAddress;
use valence_text::IntoText;

use crate::{
    plugin::{
        attack::AttackPlugin, block::BlockPlugin, bow::BowPlugin, chat::ChatPlugin,
        damage::DamagePlugin, regeneration::RegenerationPlugin, spawn::SpawnPlugin,
        stats::StatsPlugin, vanish::VanishPlugin,
    },
    skin::SkinPlugin,
};

mod command;
mod plugin;
mod skin;

#[derive(Component, Debug, Copy, Clone, PartialEq, Eq)]
pub enum Team {
    // Sorted alphabetically
    Black,
    Blue,
    Brown,
    Cyan,
    Gray,
    Green,
    LightBlue,
    LightGray,
    Lime,
    Magenta,
    Orange,
    Pink,
    Purple,
    Red,
    White,
    Yellow,
}

impl Team {
    const fn name(self) -> &'static str {
        match self {
            Self::Black => "Black",
            Self::Blue => "Blue",
            Self::Brown => "Brown",
            Self::Cyan => "Cyan",
            Self::Gray => "Gray",
            Self::Green => "Green",
            Self::LightBlue => "Light Blue",
            Self::LightGray => "Light Gray",
            Self::Lime => "Lime",
            Self::Magenta => "Magenta",
            Self::Orange => "Orange",
            Self::Pink => "Pink",
            Self::Purple => "Purple",
            Self::Red => "Red",
            Self::White => "White",
            Self::Yellow => "Yellow",
        }
    }
}

impl From<Team> for valence_text::Color {
    fn from(team: Team) -> Self {
        // Source: https://minecraft.wiki/w/Wool/DV
        // (https://web.archive.org/web/20231011122724/https://minecraft.wiki/w/Wool/DV)
        match team {
            Team::Black => Self::rgb(0x14, 0x15, 0x19),
            Team::Blue => Self::rgb(0x35, 0x39, 0x9D),
            Team::Brown => Self::rgb(0x72, 0x47, 0x28),
            Team::Cyan => Self::rgb(0x15, 0x89, 0x91),
            Team::Gray => Self::rgb(0x3E, 0x44, 0x47),
            Team::Green => Self::rgb(0x54, 0x6D, 0x1B),
            Team::LightBlue => Self::rgb(0x3A, 0xAF, 0xD9),
            Team::LightGray => Self::rgb(0x8E, 0x8E, 0x86),
            Team::Lime => Self::rgb(0x70, 0xB9, 0x19),
            Team::Magenta => Self::rgb(0xBD, 0x44, 0xB3),
            Team::Orange => Self::rgb(0xF0, 0x76, 0x13),
            Team::Pink => Self::rgb(0xED, 0x8D, 0xAC),
            Team::Purple => Self::rgb(0x79, 0x2A, 0xAC),
            Team::Red => Self::rgb(0xA1, 0x27, 0x22),
            Team::White => Self::rgb(0xE9, 0xEC, 0xEC),
            Team::Yellow => Self::rgb(0xF8, 0xC6, 0x27),
        }
    }
}

impl From<Team> for valence_text::Text {
    fn from(team: Team) -> Self {
        team.name().into_text().color(team)
    }
}

fn initialize_player(
    trigger: Trigger<'_, OnAdd, packet_state::Play>,
    mut commands: Commands<'_, '_>,
) {
    commands
        .entity(trigger.target())
        .insert((Spatial, Team::Red));
}

#[derive(Component)]
pub struct BedwarsPlugin;

impl Plugin for BedwarsPlugin {
    fn build(&self, app: &mut App) {
        app.add_plugins((
            (
                AttackPlugin,
                BlockPlugin,
                BowPlugin,
                ChatPlugin,
                DamagePlugin,
                RegenerationPlugin,
                SkinPlugin,
                SpawnPlugin,
                StatsPlugin,
                VanishPlugin,
            ),
            hyperion_clap::ClapCommandPlugin,
            hyperion_genmap::GenMapPlugin,
            hyperion_item::ItemPlugin,
            hyperion_permission::PermissionPlugin,
            hyperion_proxy_module::HyperionProxyPlugin,
        ));
        app.add_observer(initialize_player);

        command::register(app.world_mut());
    }
}

pub fn init_game(address: SocketAddr, crypto: Crypto) -> anyhow::Result<()> {
    init_game_with_proxy(ProxyBind::Tcp(address), Some(crypto))
}

pub fn build_game_app_with_proxy(
    proxy_bind: ProxyBind,
    crypto: Option<Crypto>,
) -> anyhow::Result<App> {
    let mut app = App::new();
    let tcp_address = match &proxy_bind {
        ProxyBind::Tcp(address) => Some(*address),
        ProxyBind::Iroh(_) => None,
    };

    app.insert_resource(proxy_bind);
    if let Some(crypto) = crypto {
        app.insert_resource(crypto);
    }
    app.add_plugins((HyperionCore, BedwarsPlugin));
    if let Some(address) = tcp_address {
        app.world_mut().trigger(SetProxyAddress {
            server: address.to_string(),
            ..SetProxyAddress::default()
        });
    }

    Ok(app)
}

pub fn init_game_with_proxy(proxy_bind: ProxyBind, crypto: Option<Crypto>) -> anyhow::Result<()> {
    let mut app = build_game_app_with_proxy(proxy_bind, crypto)?;
    app.run();

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
        time::Duration,
    };

    use hyperion::{IrohProxyBind, IrohSecretKey, net::Compose};
    use hyperion_proxy::{IrohServerConnection, run_proxy_iroh};
    use tokio::{net::TcpListener, runtime::Runtime, time::Instant};

    use super::*;

    const IROH_SECRET_KEY_BYTES: usize = 32;
    const SERVER_KEY_SEED: u8 = 7;
    const ALLOWED_PROXY_KEY_SEED: u8 = 8;
    const UNKNOWN_PROXY_KEY_SEED: u8 = 9;
    const EPHEMERAL_PORT: u16 = 0;
    const SMOKE_TIMEOUT: Duration = Duration::from_secs(10);
    const REJECTION_SETTLE_TIME: Duration = Duration::from_secs(1);
    const APP_UPDATE_INTERVAL: Duration = Duration::from_millis(25);

    fn secret_key_from_seed(seed: u8) -> IrohSecretKey {
        IrohSecretKey::from([seed; IROH_SECRET_KEY_BYTES])
    }

    fn localhost_socket(port: u16) -> SocketAddr {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into()
    }

    fn reserve_udp_socket_addr() -> std::io::Result<SocketAddr> {
        let socket = UdpSocket::bind(localhost_socket(EPHEMERAL_PORT))?;
        socket.local_addr()
    }

    async fn bind_player_listener() -> std::io::Result<TcpListener> {
        TcpListener::bind(localhost_socket(EPHEMERAL_PORT)).await
    }

    fn smoke_runtime() -> Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn bedwars_iroh_bind(
        server_secret: IrohSecretKey,
        bind_addr: SocketAddr,
        allowed_proxy_secret: &IrohSecretKey,
    ) -> ProxyBind {
        ProxyBind::Iroh(Box::new(IrohProxyBind {
            secret_key: Some(server_secret),
            bind_addr: Some(bind_addr),
            allowed_proxy_ids: vec![allowed_proxy_secret.public()],
        }))
    }

    fn proxy_iroh_connection(
        server_secret: &IrohSecretKey,
        server_addr: SocketAddr,
        proxy_secret: IrohSecretKey,
    ) -> IrohServerConnection {
        IrohServerConnection {
            server_id: server_secret.public(),
            direct_addrs: vec![server_addr],
            relay_urls: Vec::new(),
            secret_key: Some(proxy_secret),
            bind_addr: Some(localhost_socket(EPHEMERAL_PORT)),
        }
    }

    fn connected_proxy_count(app: &App) -> usize {
        app.world().resource::<Compose>().connected_proxy_count()
    }

    fn has_connected_proxy(app: &App) -> bool {
        connected_proxy_count(app) > 0
    }

    async fn wait_for_connected_proxy(app: &mut App) -> anyhow::Result<()> {
        let deadline = Instant::now() + SMOKE_TIMEOUT;
        loop {
            app.update();
            if has_connected_proxy(app) {
                return Ok(());
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "timed out waiting for Bedwars to register the Iroh proxy"
            );
            tokio::time::sleep(APP_UPDATE_INTERVAL).await;
        }
    }

    async fn assert_no_proxy_registered(app: &mut App) -> anyhow::Result<()> {
        let deadline = Instant::now() + REJECTION_SETTLE_TIME;
        loop {
            app.update();
            anyhow::ensure!(
                !has_connected_proxy(app),
                "Bedwars registered a proxy whose Iroh node id was not allowlisted"
            );
            if Instant::now() >= deadline {
                return Ok(());
            }
            tokio::time::sleep(APP_UPDATE_INTERVAL).await;
        }
    }

    #[test]
    fn bedwars_iroh_smoke_accepts_allowed_proxy_and_rejects_unknown_proxy() {
        let server_secret = secret_key_from_seed(SERVER_KEY_SEED);
        let allowed_proxy_secret = secret_key_from_seed(ALLOWED_PROXY_KEY_SEED);
        let unknown_proxy_secret = secret_key_from_seed(UNKNOWN_PROXY_KEY_SEED);
        let runtime = smoke_runtime();

        let accepted_server_addr = reserve_udp_socket_addr().unwrap();
        let accepted_proxy_bind = bedwars_iroh_bind(
            server_secret.clone(),
            accepted_server_addr,
            &allowed_proxy_secret,
        );
        let mut accepted_app = build_game_app_with_proxy(accepted_proxy_bind, None).unwrap();
        runtime.block_on(async {
            let accepted_listener = bind_player_listener().await.unwrap();
            let accepted_proxy = tokio::spawn(run_proxy_iroh(
                accepted_listener,
                proxy_iroh_connection(
                    &server_secret,
                    accepted_server_addr,
                    allowed_proxy_secret.clone(),
                ),
            ));

            wait_for_connected_proxy(&mut accepted_app).await.unwrap();
            accepted_proxy.abort();
        });
        drop(accepted_app);

        let rejected_server_addr = reserve_udp_socket_addr().unwrap();
        let rejected_proxy_bind = bedwars_iroh_bind(
            server_secret.clone(),
            rejected_server_addr,
            &allowed_proxy_secret,
        );
        let mut rejected_app = build_game_app_with_proxy(rejected_proxy_bind, None).unwrap();
        runtime.block_on(async {
            let rejected_listener = bind_player_listener().await.unwrap();
            let rejected_proxy = tokio::spawn(run_proxy_iroh(
                rejected_listener,
                proxy_iroh_connection(&server_secret, rejected_server_addr, unknown_proxy_secret),
            ));

            assert_no_proxy_registered(&mut rejected_app).await.unwrap();
            rejected_proxy.abort();
        });
    }
}
