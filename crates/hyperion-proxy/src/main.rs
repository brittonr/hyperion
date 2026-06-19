use std::{fmt::Debug, net::SocketAddr, path::PathBuf};

use anyhow::Context;
use clap::{Parser, ValueEnum};
use hyperion_proxy::{IrohServerConnection, run_proxy, run_proxy_iroh};
use iroh::{PublicKey, RelayUrl, SecretKey};
use serde::Deserialize;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const DEFAULT_PROXY_ADDR: &str = "0.0.0.0:25565";
const DEFAULT_SERVER_ADDR: &str = "127.0.0.1:35565";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum ServerTransport {
    #[default]
    Tcp,
    Iroh,
}

#[derive(Clone, Debug)]
enum ServerTarget {
    Tcp {
        server_addr: SocketAddr,
        server_name: String,
        root_ca_cert: PathBuf,
        cert: PathBuf,
        private_key: PathBuf,
    },
    Iroh(IrohServerConnection),
}

#[derive(Deserialize, Debug, Parser)]
#[clap(version)]
struct Params {
    /// The address for the proxy to listen on. Can be either:
    /// - A TCP address like "127.0.0.1:25565"
    /// - A Unix domain socket path like "/tmp/minecraft.sock" (Unix only)
    #[serde(default = "default_proxy_addr")]
    proxy_addr: String,

    /// The address of the target TCP Minecraft game server to proxy from/to.
    #[clap(short, long, default_value = DEFAULT_SERVER_ADDR)]
    #[serde(default = "default_server")]
    server: String,

    /// The server-side transport used between hyperion-proxy and the game server.
    #[clap(long, value_enum, default_value_t = ServerTransport::Tcp)]
    #[serde(default)]
    server_transport: ServerTransport,

    /// The file path to the root certificate authority certificate. Required for TCP transport.
    #[clap(long)]
    root_ca_cert: Option<PathBuf>,

    /// The file path to the proxy certificate. Required for TCP transport.
    #[clap(long)]
    cert: Option<PathBuf>,

    /// The file path to the proxy private key. Required for TCP transport.
    #[clap(long)]
    private_key: Option<PathBuf>,

    /// Iroh server endpoint id to dial. Required for Iroh transport.
    #[clap(long)]
    iroh_server_id: Option<PublicKey>,

    /// Direct Iroh server socket address. Repeat for multiple direct addresses.
    #[clap(long)]
    #[serde(default)]
    iroh_server_addr: Vec<SocketAddr>,

    /// Iroh relay URL for the server endpoint. Iroh 0.35 supports at most one relay URL here.
    #[clap(long)]
    #[serde(default)]
    iroh_server_relay: Vec<RelayUrl>,

    /// Optional stable Iroh secret key for this proxy endpoint. Ephemeral if omitted.
    #[clap(long)]
    iroh_secret_key: Option<SecretKey>,

    /// Optional local UDP socket for Iroh to bind, for example 0.0.0.0:0.
    #[clap(long)]
    iroh_bind_addr: Option<SocketAddr>,
}

fn default_proxy_addr() -> String {
    DEFAULT_PROXY_ADDR.to_string()
}

fn default_server() -> String {
    DEFAULT_SERVER_ADDR.to_string()
}

#[derive(Debug)]
enum ProxyAddress {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

use std::{fmt::Display, task::Poll};

use colored::Colorize;
use tokio_util::net::Listener;

impl Display for ProxyAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "tcp://{addr}"),
            #[cfg(unix)]
            Self::Unix(path) => write!(f, "unix://{}", path.display()),
        }
    }
}

impl ProxyAddress {
    fn parse(addr: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if addr.contains(':') {
            Ok(Self::Tcp(addr.parse()?))
        } else {
            #[cfg(unix)]
            {
                Ok(Self::Unix(PathBuf::from(addr)))
            }
            #[cfg(not(unix))]
            {
                Err("Unix sockets are not supported on this platform".into())
            }
        }
    }
}

fn required_path(path: &Option<PathBuf>, flag: &'static str) -> anyhow::Result<PathBuf> {
    path.clone()
        .with_context(|| format!("TCP transport requires --{flag}"))
}

fn iroh_server_connection(params: &Params) -> anyhow::Result<IrohServerConnection> {
    let server_id = params
        .iroh_server_id
        .with_context(|| "Iroh transport requires --iroh-server-id")?;

    Ok(IrohServerConnection {
        server_id,
        direct_addrs: params.iroh_server_addr.clone(),
        relay_urls: params.iroh_server_relay.clone(),
        secret_key: params.iroh_secret_key.clone(),
        bind_addr: params.iroh_bind_addr,
    })
}

async fn server_target_from_params(params: &Params) -> anyhow::Result<ServerTarget> {
    match params.server_transport {
        ServerTransport::Tcp => {
            let server_addr: SocketAddr = tokio::net::lookup_host(&params.server)
                .await
                .context("failed to resolve TCP server host")?
                .next()
                .with_context(|| format!("Could not resolve hostname: {}", params.server))?;

            Ok(ServerTarget::Tcp {
                server_addr,
                server_name: params.server.clone(),
                root_ca_cert: required_path(&params.root_ca_cert, "root-ca-cert")?,
                cert: required_path(&params.cert, "cert")?,
                private_key: required_path(&params.private_key, "private-key")?,
            })
        }
        ServerTransport::Iroh => Ok(ServerTarget::Iroh(iroh_server_connection(params)?)),
    }
}

async fn run_with_server_target<L>(listener: L, server_target: ServerTarget) -> anyhow::Result<()>
where
    L: Listener<Io: Send, Addr: Debug> + 'static,
{
    match server_target {
        ServerTarget::Tcp {
            server_addr,
            server_name,
            root_ca_cert,
            cert,
            private_key,
        } => {
            run_proxy(
                listener,
                server_addr,
                server_name,
                &root_ca_cert,
                &cert,
                &private_key,
            )
            .await
        }
        ServerTarget::Iroh(server) => run_proxy_iroh(listener, server).await,
    }
}

fn setup_logging() {
    // Build a custom subscriber
    tracing_subscriber::fmt()
        .with_ansi(true)
        .with_file(false)
        .with_line_number(false)
        .with_target(false)
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file if available
    dotenvy::dotenv().ok();

    setup_logging();

    // Try to load params from environment variables
    let params = match envy::prefixed("HYPERION_PROXY_").from_env::<Params>() {
        Ok(params) => {
            info!("Loaded configuration from environment variables");
            params
        }
        Err(e) => {
            info!(
                "Failed to load from environment: {}, falling back to command line arguments",
                e
            );
            Params::parse()
        }
    };

    let proxy_addr = ProxyAddress::parse(&params.proxy_addr)
        .map_err(|err| anyhow::anyhow!("failed to parse proxy address: {err}"))?;
    let server_target = server_target_from_params(&params).await?;

    let login_help = "~ The address to connect to".dimmed();

    info!("Starting Hyperion Proxy");
    info!("📡 Public proxy address: {proxy_addr} {login_help}",);

    let server_help = "~ The event server internal address".dimmed();
    match &server_target {
        ServerTarget::Tcp { server_addr, .. } => {
            info!("👾 Internal server address: tcp://{server_addr} {server_help}");
        }
        ServerTarget::Iroh(server) => {
            info!(
                "👾 Internal server address: iroh://{:?} {server_help}",
                server.node_addr()
            );
        }
    }

    let handle = tokio::spawn(async move {
        match &proxy_addr {
            ProxyAddress::Tcp(addr) => {
                let listener = TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("failed to bind TCP proxy listener at {addr}"))?;
                let socket = NoDelayTcpListener { listener };
                run_with_server_target(socket, server_target).await?;
            }
            #[cfg(unix)]
            ProxyAddress::Unix(path) => {
                // remove file if already exists
                let _unused = tokio::fs::remove_file(path).await;
                let listener = UnixListener::bind(path).with_context(|| {
                    format!("failed to bind Unix proxy listener at {}", path.display())
                })?;
                run_with_server_target(listener, server_target).await?;
            }
        }
        anyhow::Ok(())
    });

    match handle.await {
        Ok(Ok(())) => {
            info!("Proxy task completed successfully");
            Ok(())
        }
        Ok(Err(err)) => {
            error!(?err, "Proxy task failed");
            Err(err)
        }
        Err(err) => {
            error!(?err, "Proxy task join failed");
            Err(anyhow::anyhow!("proxy task join failed: {err}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IROH_SECRET_KEY_BYTES: usize = 32;
    const SERVER_KEY_SEED: u8 = 1;

    fn server_secret_key() -> SecretKey {
        SecretKey::from([SERVER_KEY_SEED; IROH_SECRET_KEY_BYTES])
    }

    fn params_for_transport(server_transport: ServerTransport) -> Params {
        Params {
            proxy_addr: default_proxy_addr(),
            server: default_server(),
            server_transport,
            root_ca_cert: None,
            cert: None,
            private_key: None,
            iroh_server_id: None,
            iroh_server_addr: Vec::new(),
            iroh_server_relay: Vec::new(),
            iroh_secret_key: None,
            iroh_bind_addr: None,
        }
    }

    #[test]
    fn tcp_transport_accepts_present_tls_paths() {
        let mut params = params_for_transport(ServerTransport::Tcp);
        params.root_ca_cert = Some(PathBuf::from("root_ca.crt"));
        params.cert = Some(PathBuf::from("proxy.crt"));
        params.private_key = Some(PathBuf::from("proxy_private_key.pem"));

        assert!(required_path(&params.root_ca_cert, "root-ca-cert").is_ok());
        assert!(required_path(&params.cert, "cert").is_ok());
        assert!(required_path(&params.private_key, "private-key").is_ok());
    }

    #[test]
    fn tcp_transport_rejects_missing_tls_paths() {
        let params = params_for_transport(ServerTransport::Tcp);

        let err = required_path(&params.root_ca_cert, "root-ca-cert").unwrap_err();

        assert!(err.to_string().contains("--root-ca-cert"));
    }

    #[test]
    fn iroh_transport_requires_server_id() {
        let params = params_for_transport(ServerTransport::Iroh);

        let err = iroh_server_connection(&params).unwrap_err();

        assert!(err.to_string().contains("--iroh-server-id"));
    }

    #[test]
    fn iroh_transport_builds_server_connection() {
        let mut params = params_for_transport(ServerTransport::Iroh);
        let server_secret = server_secret_key();
        params.iroh_server_id = Some(server_secret.public());

        let connection = iroh_server_connection(&params).unwrap();

        assert_eq!(connection.server_id, server_secret.public());
    }
}

struct NoDelayTcpListener {
    listener: TcpListener,
}

impl Listener for NoDelayTcpListener {
    type Addr = <TcpListener as Listener>::Addr;
    type Io = <TcpListener as Listener>::Io;

    fn poll_accept(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<std::io::Result<(Self::Io, Self::Addr)>> {
        let Poll::Ready(result) = self.listener.poll_accept(cx) else {
            return Poll::Pending;
        };

        let Ok((socket, addr)) = result else {
            return Poll::Ready(result);
        };

        match socket.set_nodelay(true) {
            Ok(..) => Poll::Ready(Ok((socket, addr))),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}
