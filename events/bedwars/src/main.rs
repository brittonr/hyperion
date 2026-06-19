use std::{net::SocketAddr, path::PathBuf};

use anyhow::Context;
use bedwars::init_game_with_proxy;
use clap::{Parser, ValueEnum};
use hyperion::{Crypto, IrohProxyBind, IrohPublicKey, IrohSecretKey, ProxyBind};
use serde::Deserialize;
use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt};
// use tracing_tracy::TracyLayer;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const DEFAULT_SERVER_IP: &str = "0.0.0.0";
const DEFAULT_SERVER_PORT: u16 = 35565;
const PROCESS_NAME_ARG_COUNT: usize = 1;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum ProxyTransport {
    #[default]
    Tcp,
    Iroh,
}

/// The arguments to run the server
#[derive(Parser, Deserialize, Debug)]
struct Args {
    /// The IP address the TCP proxy listener should bind. Ignored by Iroh transport.
    #[clap(short, long, default_value = DEFAULT_SERVER_IP)]
    #[serde(default = "default_ip")]
    ip: String,

    /// The TCP proxy listener port. Ignored by Iroh transport.
    #[clap(short, long, default_value_t = DEFAULT_SERVER_PORT)]
    #[serde(default = "default_port")]
    port: u16,

    /// The server-to-proxy transport.
    #[clap(long, value_enum, default_value_t = ProxyTransport::Tcp)]
    #[serde(default)]
    proxy_transport: ProxyTransport,

    /// The file path to the root certificate authority's certificate. Required for TCP transport.
    #[clap(long)]
    root_ca_cert: Option<PathBuf>,

    /// The file path to the game server's certificate. Required for TCP transport.
    #[clap(long)]
    cert: Option<PathBuf>,

    /// The file path to the game server's private key. Required for TCP transport.
    #[clap(long)]
    private_key: Option<PathBuf>,

    /// Optional stable Iroh secret key for this server endpoint. Ephemeral if omitted.
    #[clap(long)]
    iroh_secret_key: Option<IrohSecretKey>,

    /// Optional local UDP socket for Iroh to bind, for example 0.0.0.0:0.
    #[clap(long)]
    iroh_bind_addr: Option<SocketAddr>,

    /// Allowed Iroh proxy endpoint id. Repeat to allow multiple proxies. Empty allows any proxy.
    #[clap(long)]
    #[serde(default)]
    iroh_allowed_proxy_id: Vec<IrohPublicKey>,
}

fn default_ip() -> String {
    DEFAULT_SERVER_IP.to_string()
}

const fn default_port() -> u16 {
    DEFAULT_SERVER_PORT
}

fn required_path<'a>(path: Option<&'a PathBuf>, flag: &'static str) -> anyhow::Result<&'a PathBuf> {
    path.with_context(|| format!("TCP transport requires --{flag}"))
}

fn tcp_crypto(args: &Args) -> anyhow::Result<Crypto> {
    let root_ca_cert = required_path(args.root_ca_cert.as_ref(), "root-ca-cert")?;
    let cert = required_path(args.cert.as_ref(), "cert")?;
    let private_key = required_path(args.private_key.as_ref(), "private-key")?;

    Crypto::new(root_ca_cert, cert, private_key).context("failed to load TCP mTLS material")
}

fn proxy_bind_from_args(
    args: &Args,
    tcp_address: SocketAddr,
) -> anyhow::Result<(ProxyBind, Option<Crypto>)> {
    match args.proxy_transport {
        ProxyTransport::Tcp => Ok((ProxyBind::Tcp(tcp_address), Some(tcp_crypto(args)?))),
        ProxyTransport::Iroh => Ok((
            ProxyBind::Iroh(Box::new(IrohProxyBind {
                secret_key: args.iroh_secret_key.clone(),
                bind_addr: args.iroh_bind_addr,
                allowed_proxy_ids: args.iroh_allowed_proxy_id.clone(),
            })),
            None,
        )),
    }
}

const fn cli_args_present(arg_count: usize) -> bool {
    arg_count > PROCESS_NAME_ARG_COUNT
}

fn args_from_config() -> Args {
    if cli_args_present(std::env::args_os().len()) {
        return Args::parse();
    }

    match envy::prefixed("BEDWARS_").from_env::<Args>() {
        Ok(args) => {
            tracing::info!("Loaded configuration from environment variables");
            args
        }
        Err(e) => {
            tracing::info!(
                "Failed to load from environment: {}, falling back to command line arguments",
                e
            );
            Args::parse()
        }
    }
}

fn setup_logging() {
    tracing::subscriber::set_global_default(
        Registry::default()
            .with(EnvFilter::from_default_env())
            // .with(TracyLayer::default())
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(false)
                    .with_thread_ids(false)
                    .with_file(true)
                    .with_line_number(true),
            ),
    )
    .expect("setup tracing subscribers");
}

fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    setup_logging();

    let args = args_from_config();

    let address = format!("{ip}:{port}", ip = args.ip, port = args.port);
    let address = address
        .parse::<SocketAddr>()
        .context("failed to parse TCP proxy address")?;
    let (proxy_bind, crypto) = proxy_bind_from_args(&args, address)?;

    init_game_with_proxy(proxy_bind, crypto)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOOPBACK_IPV4_OCTETS: [u8; 4] = [127, 0, 0, 1];

    fn args_for_transport(proxy_transport: ProxyTransport) -> Args {
        Args {
            ip: default_ip(),
            port: default_port(),
            proxy_transport,
            root_ca_cert: None,
            cert: None,
            private_key: None,
            iroh_secret_key: None,
            iroh_bind_addr: None,
            iroh_allowed_proxy_id: Vec::new(),
        }
    }

    #[test]
    fn cli_args_present_rejects_process_name_only() {
        assert!(!cli_args_present(PROCESS_NAME_ARG_COUNT));
    }

    #[test]
    fn cli_args_present_accepts_extra_args() {
        assert!(cli_args_present(PROCESS_NAME_ARG_COUNT + 1));
    }

    #[test]
    fn tcp_transport_accepts_present_tls_paths() {
        let mut args = args_for_transport(ProxyTransport::Tcp);
        args.root_ca_cert = Some(PathBuf::from("root_ca.crt"));
        args.cert = Some(PathBuf::from("server.crt"));
        args.private_key = Some(PathBuf::from("server_private_key.pem"));

        assert!(required_path(args.root_ca_cert.as_ref(), "root-ca-cert").is_ok());
        assert!(required_path(args.cert.as_ref(), "cert").is_ok());
        assert!(required_path(args.private_key.as_ref(), "private-key").is_ok());
    }

    #[test]
    fn tcp_transport_rejects_missing_tls_paths() {
        let args = args_for_transport(ProxyTransport::Tcp);

        let err = required_path(args.root_ca_cert.as_ref(), "root-ca-cert").unwrap_err();

        assert!(err.to_string().contains("--root-ca-cert"));
    }

    #[test]
    fn iroh_transport_builds_without_tls_paths() {
        let args = args_for_transport(ProxyTransport::Iroh);
        let tcp_address = SocketAddr::from((LOOPBACK_IPV4_OCTETS, DEFAULT_SERVER_PORT));
        let (proxy_bind, crypto) = proxy_bind_from_args(&args, tcp_address).unwrap();

        assert!(matches!(proxy_bind, ProxyBind::Iroh(_)));
        assert!(crypto.is_none());
    }
}
