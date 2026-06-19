#![allow(
    clippy::module_inception,
    clippy::module_name_repetitions,
    clippy::derive_partial_eq_without_eq,
    hidden_glob_reexports
)]

mod proxy_to_server;
mod server_to_proxy;
mod shared;

pub const IROH_PROXY_ALPN: &[u8] = b"hyperion/proxy/1";

pub use proxy_to_server::*;
pub use server_to_proxy::*;
pub use shared::*;
