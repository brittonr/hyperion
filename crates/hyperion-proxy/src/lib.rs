#![feature(maybe_uninit_slice)]
#![feature(allocator_api)]
#![feature(let_chains)]
#![feature(never_type)]
#![feature(stmt_expr_attributes)]
#![feature(gen_blocks)]
#![allow(
    clippy::redundant_pub_crate,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::missing_panics_doc,
    clippy::module_inception,
    clippy::future_not_send
)]

use std::{fmt::Debug, net::SocketAddr, path::Path, sync::Arc, time::Duration};

use anyhow::Context;
use colored::Colorize;
use hyperion_proto::{ArchivedServerToProxyMessage, ProxyToServerMessage};
use iroh::{Endpoint as IrohEndpoint, NodeAddr, PublicKey, RelayUrl, SecretKey};
use rkyv::util::AlignedVec;
use rustc_hash::FxBuildHasher;
use rustls::{RootCertStore, client::ClientConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use tokio::{
    io::{AsyncRead, AsyncReadExt, BufReader},
    net::{TcpStream, ToSocketAddrs},
};
use tokio_rustls::TlsConnector;
use tokio_util::net::Listener;
use tracing::{Instrument, debug, error, info, info_span, instrument, trace, warn};

use crate::{
    cache::BufferedEgress,
    data::PlayerHandle,
    egress::Egress,
    player::initiate_player_connection,
    server_sender::{ServerSender, launch_server_writer},
};

/// 4 KiB
const DEFAULT_BUFFER_SIZE: usize = 4 * 1024;

#[derive(Debug, Clone)]
pub struct IrohServerConnection {
    pub server_id: PublicKey,
    pub direct_addrs: Vec<SocketAddr>,
    pub relay_urls: Vec<RelayUrl>,
    pub secret_key: Option<SecretKey>,
    pub bind_addr: Option<SocketAddr>,
}

impl IrohServerConnection {
    #[must_use]
    pub fn node_addr(&self) -> NodeAddr {
        NodeAddr::from_parts(
            self.server_id,
            self.relay_urls.first().cloned(),
            self.direct_addrs.clone(),
        )
    }
}

fn validate_iroh_server_connection(server: &IrohServerConnection) -> anyhow::Result<()> {
    anyhow::ensure!(
        server.relay_urls.len() <= MAX_SUPPORTED_IROH_RELAY_URLS,
        "Iroh 0.35 supports at most one relay URL per server address"
    );
    Ok(())
}

/// Maximum number of pending messages in a player's communication channel.
/// If this limit is exceeded, the player will be disconnected to prevent
/// memory exhaustion from slow or unresponsive clients.
const MAX_PLAYER_PENDING_MESSAGES: usize = 1_024;
const SERVER_CONNECT_RETRY_DELAY: Duration = Duration::from_millis(100);
const MAX_SUPPORTED_IROH_RELAY_URLS: usize = 1;

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        task::{Context, Poll},
    };

    use anyhow::Context as _;
    use hyperion_proto::ArchivedProxyToServerMessage;
    use tokio::io::AsyncReadExt as _;

    use super::*;

    const IROH_SECRET_KEY_BYTES: usize = 32;
    const SERVER_KEY_SEED: u8 = 1;
    const PROXY_KEY_SEED: u8 = 2;
    const FIRST_RELAY_URL: &str = "https://relay-one.example.com";
    const SECOND_RELAY_URL: &str = "https://relay-two.example.com";
    const SMOKE_TIMEOUT: Duration = Duration::from_secs(10);
    const EPHEMERAL_PORT: u16 = 0;

    struct PendingListener;

    impl Listener for PendingListener {
        type Addr = SocketAddr;
        type Io = tokio::io::DuplexStream;

        fn poll_accept(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<std::io::Result<(Self::Io, Self::Addr)>> {
            Poll::Pending
        }

        fn local_addr(&self) -> std::io::Result<Self::Addr> {
            Ok(SocketAddrV4::new(Ipv4Addr::LOCALHOST, EPHEMERAL_PORT).into())
        }
    }

    fn relay_url(value: &str) -> RelayUrl {
        value.parse().unwrap()
    }

    fn secret_key_from_seed(seed: u8) -> SecretKey {
        SecretKey::from([seed; IROH_SECRET_KEY_BYTES])
    }

    fn local_iroh_bind_addr() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, EPHEMERAL_PORT)
    }

    fn direct_node_addr(endpoint: &IrohEndpoint) -> NodeAddr {
        let (ipv4_addr, ipv6_addr) = endpoint.bound_sockets();
        let mut direct_addrs = vec![ipv4_addr];
        if let Some(ipv6_addr) = ipv6_addr {
            direct_addrs.push(ipv6_addr);
        }

        NodeAddr::from_parts(endpoint.node_id(), None, direct_addrs)
    }

    fn server_connection(relay_urls: Vec<RelayUrl>) -> IrohServerConnection {
        let secret_key = secret_key_from_seed(SERVER_KEY_SEED);
        IrohServerConnection {
            server_id: secret_key.public(),
            direct_addrs: Vec::new(),
            relay_urls,
            secret_key: None,
            bind_addr: None,
        }
    }

    async fn bind_smoke_server() -> anyhow::Result<IrohEndpoint> {
        IrohEndpoint::builder()
            .secret_key(secret_key_from_seed(SERVER_KEY_SEED))
            .bind_addr_v4(local_iroh_bind_addr())
            .alpns(vec![IROH_PROXY_ALPN.to_vec()])
            .bind()
            .await
            .context("binding Iroh smoke server")
    }

    async fn bind_smoke_proxy() -> anyhow::Result<IrohEndpoint> {
        IrohEndpoint::builder()
            .secret_key(secret_key_from_seed(PROXY_KEY_SEED))
            .bind_addr_v4(local_iroh_bind_addr())
            .bind()
            .await
            .context("binding Iroh smoke proxy")
    }

    async fn accept_proxy_ready(endpoint: IrohEndpoint) -> anyhow::Result<bool> {
        let connection = endpoint
            .accept()
            .await
            .context("Iroh smoke server accepted no incoming connection")?
            .await
            .context("accepting Iroh smoke connection")?;
        let (_send, mut recv) = connection
            .accept_bi()
            .await
            .context("accepting Iroh smoke bidirectional stream")?;

        let len = recv.read_u64().await.context("reading ProxyReady length")?;
        let len = usize::try_from(len).context("ProxyReady length does not fit usize")?;
        let mut buffer = vec![0; len];
        recv.read_exact(&mut buffer)
            .await
            .context("reading ProxyReady bytes")?;

        let message =
            unsafe { rkyv::access_unchecked::<ArchivedProxyToServerMessage<'_>>(&buffer) };
        Ok(matches!(message, ArchivedProxyToServerMessage::ProxyReady))
    }

    #[test]
    fn iroh_server_connection_accepts_single_relay_url() {
        let server = server_connection(vec![relay_url(FIRST_RELAY_URL)]);

        assert!(validate_iroh_server_connection(&server).is_ok());
    }

    #[test]
    fn iroh_server_connection_rejects_multiple_relay_urls() {
        let server = server_connection(vec![
            relay_url(FIRST_RELAY_URL),
            relay_url(SECOND_RELAY_URL),
        ]);

        let err = validate_iroh_server_connection(&server).unwrap_err();

        assert!(err.to_string().contains("at most one relay URL"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn iroh_proxy_smoke_sends_proxy_ready() {
        let server_endpoint = bind_smoke_server().await.unwrap();
        let proxy_endpoint = bind_smoke_proxy().await.unwrap();
        let server_addr = direct_node_addr(&server_endpoint);
        let server_task = tokio::spawn(accept_proxy_ready(server_endpoint));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(None);
        let mut listener = PendingListener;
        let proxy_task = tokio::spawn(async move {
            connect_to_iroh_server_and_run_proxy(
                &mut listener,
                proxy_endpoint,
                server_addr,
                shutdown_rx,
                shutdown_tx,
            )
            .await
        });

        let is_proxy_ready = tokio::time::timeout(SMOKE_TIMEOUT, server_task)
            .await
            .expect("Iroh smoke timed out waiting for ProxyReady")
            .expect("Iroh smoke server task panicked")
            .expect("Iroh smoke server failed");
        assert!(is_proxy_ready);

        proxy_task.abort();
    }
}

pub mod cache;
pub mod data;
pub mod egress;
pub mod player;
pub mod server_sender;
pub mod util;

pub use hyperion_proto::IROH_PROXY_ALPN;

fn proxy_ready_message() -> anyhow::Result<AlignedVec> {
    rkyv::to_bytes::<rkyv::rancor::Error>(&ProxyToServerMessage::ProxyReady)
        .context("failed to encode proxy ready message")
}

#[tracing::instrument(level = "trace", skip_all)]
async fn connect(addr: impl ToSocketAddrs + Debug + Clone) -> TcpStream {
    loop {
        if let Ok(stream) = TcpStream::connect(addr.clone()).await {
            return stream;
        }

        tokio::time::sleep(SERVER_CONNECT_RETRY_DELAY).await;
    }
}

#[derive(Debug, PartialEq)]
enum ShutdownType {
    Reconnect,
    Full,
}

#[tracing::instrument(level = "trace", skip_all)]
pub async fn run_proxy(
    mut listener: impl HyperionListener,
    server_addr: impl ToSocketAddrs + Debug + Clone,
    mut server_name: String,
    root_ca_cert_path: &Path,
    proxy_cert_path: &Path,
    proxy_private_key_path: &Path,
) -> anyhow::Result<()> {
    // Remove port
    let Some(port_index) = server_name.rfind(':') else {
        anyhow::bail!("server name is missing port");
    };
    server_name.truncate(port_index);

    let server_name = ServerName::try_from(server_name).context("failed to parse server name")?;

    let root_ca_cert = CertificateDer::from_pem_file(root_ca_cert_path)
        .context("failed to load root certificate authority certificate")?;
    let proxy_cert = CertificateDer::from_pem_file(proxy_cert_path)
        .context("failed to load proxy certificate")?;

    let root_cert_store = Arc::new(RootCertStore {
        roots: vec![
            webpki::anchor_from_trusted_cert(&root_ca_cert)
                .context("failed to create trust anchor")?
                .to_owned(),
        ],
    });

    let cert_chain = vec![proxy_cert, root_ca_cert];
    let key_der = PrivateKeyDer::from_pem_file(proxy_private_key_path)
        .context("failed to load proxy private key")?;

    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_client_auth_cert(cert_chain, key_der)
            .context("failed to create tls client config")?,
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(None);

    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to register SIGTERM handler")?;

    #[cfg(unix)]
    let mut sigquit = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::quit())
        .context("failed to register SIGQUIT handler")?;

    #[cfg(unix)]
    tokio::spawn({
        let shutdown_tx = shutdown_tx.clone();
        async move {
            tokio::select! {
                _ = sigterm.recv() => {
                    warn!("SIGTERM received, shutting down");
                    shutdown_tx.send(Some(ShutdownType::Full)).unwrap();
                }
                _ = sigquit.recv() => {
                    warn!("SIGQUIT received, shutting down");
                    shutdown_tx.send(Some(ShutdownType::Full)).unwrap();
                }
            }
        }
    });

    loop {
        let mut shutdown_rx2 = shutdown_rx.clone();

        if *shutdown_rx2.borrow() == Some(ShutdownType::Full) {
            break Ok(());
        }

        tokio::select! {
            _ = shutdown_rx2.wait_for(|value| *value == Some(ShutdownType::Full)) => {
                warn!("Received shutdown signal, exiting proxy loop");
                break Ok(());
            }
            () = async {

                // clear shutdown channel
                shutdown_tx.send(None).unwrap();

                let binding_help = "~ Make sure the event server is running".dimmed();
                info!("⏳ Binding to server... {binding_help}");

                let server_socket = connect(server_addr.clone()).await;
                server_socket.set_nodelay(true).unwrap();

                if let Err(e) = connect_to_tcp_server_and_run_proxy(&mut listener, server_socket, server_name.clone(), config.clone(), shutdown_rx.clone(), shutdown_tx.clone()).await {
                    error!("Error connecting to server: {e:?}");
                }


            } => {}
        }
    }
}

#[tracing::instrument(level = "trace", skip_all)]
pub async fn run_proxy_iroh(
    mut listener: impl HyperionListener,
    server: IrohServerConnection,
) -> anyhow::Result<()> {
    validate_iroh_server_connection(&server)?;

    let mut builder = IrohEndpoint::builder().discovery_n0();
    if let Some(secret_key) = server.secret_key.clone() {
        builder = builder.secret_key(secret_key);
    }
    if let Some(bind_addr) = server.bind_addr {
        builder = match bind_addr {
            SocketAddr::V4(addr) => builder.bind_addr_v4(addr),
            SocketAddr::V6(addr) => builder.bind_addr_v6(addr),
        };
    }

    let endpoint = builder
        .bind()
        .await
        .context("failed to bind Iroh proxy endpoint")?;
    let server_addr = server.node_addr();
    info!(
        endpoint_id = %endpoint.node_id(),
        bound_sockets = ?endpoint.bound_sockets(),
        server_addr = ?server_addr,
        "Starting Hyperion Proxy over Iroh"
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(None);

    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to register SIGTERM handler")?;

    #[cfg(unix)]
    let mut sigquit = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::quit())
        .context("failed to register SIGQUIT handler")?;

    #[cfg(unix)]
    tokio::spawn({
        let shutdown_tx = shutdown_tx.clone();
        async move {
            tokio::select! {
                _ = sigterm.recv() => {
                    warn!("SIGTERM received, shutting down");
                    shutdown_tx.send(Some(ShutdownType::Full)).unwrap();
                }
                _ = sigquit.recv() => {
                    warn!("SIGQUIT received, shutting down");
                    shutdown_tx.send(Some(ShutdownType::Full)).unwrap();
                }
            }
        }
    });

    loop {
        let mut shutdown_rx2 = shutdown_rx.clone();

        if *shutdown_rx2.borrow() == Some(ShutdownType::Full) {
            break Ok(());
        }

        tokio::select! {
            _ = shutdown_rx2.wait_for(|value| *value == Some(ShutdownType::Full)) => {
                warn!("Received shutdown signal, exiting Iroh proxy loop");
                break Ok(());
            }
            () = async {
                shutdown_tx.send(None).unwrap();

                let binding_help = "~ Make sure the Iroh event server is running".dimmed();
                info!("⏳ Binding to Iroh server... {binding_help}");

                if let Err(e) = connect_to_iroh_server_and_run_proxy(&mut listener, endpoint.clone(), server_addr.clone(), shutdown_rx.clone(), shutdown_tx.clone()).await {
                    error!("Error connecting to Iroh server: {e:?}");
                }
            } => {}
        }
    }
}

#[tracing::instrument(level = "trace", skip_all)]
async fn connect_to_iroh_server_and_run_proxy(
    listener: &mut impl HyperionListener,
    endpoint: IrohEndpoint,
    server_addr: NodeAddr,
    shutdown_rx: tokio::sync::watch::Receiver<Option<ShutdownType>>,
    shutdown_tx: tokio::sync::watch::Sender<Option<ShutdownType>>,
) -> anyhow::Result<()> {
    let connection = endpoint
        .connect(server_addr, IROH_PROXY_ALPN)
        .await
        .context("failed to connect to Iroh game server")?;
    let (server_write, server_read) = connection
        .open_bi()
        .await
        .context("failed to open Iroh proxy stream")?;
    let server_sender = launch_server_writer(server_write);
    server_sender
        .send(proxy_ready_message()?)
        .await
        .map_err(|err| anyhow::anyhow!("failed to send proxy ready message: {err}"))?;

    info!("🔗 Connected to Iroh server, accepting player connections");
    let result = run_proxy_on_server_stream(
        listener,
        server_read,
        server_sender,
        shutdown_rx,
        shutdown_tx,
    )
    .await;
    drop(connection);
    result
}

#[tracing::instrument(level = "trace", skip_all)]
async fn connect_to_tcp_server_and_run_proxy(
    listener: &mut impl HyperionListener,
    server_socket: TcpStream,
    server_name: ServerName<'static>,
    config: Arc<ClientConfig>,
    shutdown_rx: tokio::sync::watch::Receiver<Option<ShutdownType>>,
    shutdown_tx: tokio::sync::watch::Sender<Option<ShutdownType>>,
) -> anyhow::Result<()> {
    info!("🔗 Connected to TCP server, accepting connections");

    let connector = TlsConnector::from(config);
    let server_stream = connector
        .connect(server_name, server_socket)
        .await
        .context("failed to connect to game server")?;

    let (server_read, server_write) = tokio::io::split(server_stream);
    let server_sender = launch_server_writer(server_write);
    let result = run_proxy_on_server_stream(
        listener,
        server_read,
        server_sender,
        shutdown_rx,
        shutdown_tx,
    )
    .await;
    drop(connector);
    result
}

#[tracing::instrument(level = "trace", skip_all)]
async fn run_proxy_on_server_stream<R>(
    listener: &mut impl HyperionListener,
    server_read: R,
    server_sender: ServerSender,
    shutdown_rx: tokio::sync::watch::Receiver<Option<ShutdownType>>,
    shutdown_tx: tokio::sync::watch::Sender<Option<ShutdownType>>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let player_registry = papaya::HashMap::default();
    let player_registry: &'static papaya::HashMap<u64, PlayerHandle, FxBuildHasher> =
        Box::leak(Box::new(player_registry));

    let egress = Egress::new(player_registry, server_sender.clone());

    let egress = BufferedEgress::new(egress);

    let mut handler = IngressHandler::new(BufReader::new(server_read), egress);

    tokio::spawn({
        let mut shutdown_rx = shutdown_rx.clone();

        async move {
                loop {
                    tokio::select! {
                    _ = shutdown_rx.wait_for(Option::is_some) => return,
                    result = handler.handle_next() => {
                        match result {
                            Ok(()) => {},
                            Err(e) => {
                                error!(
                                    "Error reading next packet: {e:?}. Are you connected to a valid \
                                     hyperion server? If you are connected to a vanilla server, \
                                     hyperion-proxy will not work."
                                );
                                break;
                            }
                        }
                    }
                }
                }

                debug!("Sending shutdown to all players");

                shutdown_tx.send(Some(ShutdownType::Reconnect)).unwrap();
            }
                .instrument(info_span!("server_reader_loop"))
    });

    // 0 is reserved for "None" value
    let mut player_id_on = 1;

    loop {
        let mut shutdown_rx = shutdown_rx.clone();
        let socket = tokio::select! {
            _ = shutdown_rx.wait_for(Option::is_some) => {
                return Ok(())
            }
            Ok((socket, addr)) = listener.accept() => {
                info!("New client connection from {addr:?}");
                socket
            }
        };

        let registry = player_registry.pin();

        // todo: re-add bounding but issues if have MASSIVE number of packets
        let (tx, rx) = kanal::bounded_async(MAX_PLAYER_PENDING_MESSAGES);
        registry.insert(player_id_on, PlayerHandle::new(tx));

        // todo: some SlotMap like thing
        debug!("got player with id {player_id_on:?}");

        initiate_player_connection(
            socket,
            shutdown_rx.clone(),
            player_id_on,
            rx,
            server_sender.clone(),
            player_registry,
        );

        player_id_on += 1;
    }
}

struct IngressHandler<R> {
    server_read: BufReader<R>,
    buffer: Vec<u8>,
    egress: BufferedEgress,
}

impl<R> Debug for IngressHandler<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerReader").finish()
    }
}

impl<R> IngressHandler<R>
where
    R: AsyncRead + Unpin,
{
    pub fn new(server_read: BufReader<R>, egress: BufferedEgress) -> Self {
        Self {
            server_read,
            egress,
            buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
        }
    }

    // #[instrument(level = "info", skip_all, name = "ServerReader::next")]
    pub async fn handle_next(&mut self) -> anyhow::Result<()> {
        let len = self.read_len().await?;
        let len = usize::try_from(len).context("Failed to convert len to usize")?;

        debug_assert!(len <= 1_000_000);

        trace!("Received packet of length {len}");

        self.handle_next_server_packet(len).await
    }

    #[instrument(level = "trace")]
    async fn read_len(&mut self) -> anyhow::Result<u64> {
        self.server_read
            .read_u64()
            .await
            .context("Failed to read int")
    }

    #[instrument(level = "trace")]
    async fn handle_next_server_packet(&mut self, len: usize) -> anyhow::Result<()> {
        // [A]
        if self.buffer.len() < len {
            self.buffer.resize(len, 0);
        }

        #[expect(
            clippy::indexing_slicing,
            reason = "we already verified in [A] that length of buffer is at least {len}"
        )]
        let slice = &mut self.buffer[..len];
        self.server_read.read_exact(slice).await?;

        let result = unsafe { rkyv::access_unchecked::<ArchivedServerToProxyMessage<'_>>(slice) };

        self.egress.handle_packet(result);

        Ok(())
    }
}

pub trait HyperionListener: Listener<Io: Send, Addr: Debug> + 'static {}

impl<L: Listener<Io: Send, Addr: Debug> + 'static> HyperionListener for L {}
