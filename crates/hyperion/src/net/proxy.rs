//! Communication to a proxy which forwards packets to the players.

use std::{
    mem::size_of,
    net::SocketAddr,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use bevy::prelude::*;
use hyperion_proto::{ArchivedProxyToServerMessage, IROH_PROXY_ALPN};
use hyperion_utils::EntityExt;
use iroh::{Endpoint as IrohEndpoint, PublicKey, SecretKey};
use rustc_hash::FxHashMap;
use rustls::{
    RootCertStore,
    server::{ServerConfig, WebPkiClientVerifier},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use valence_protocol::{VarInt, packets::play};

use crate::{
    ConnectionId, Crypto, PacketDecoder,
    command_channel::CommandChannel,
    net::{Channel, ChannelId, Compose, IoBuf, ProxyId},
    runtime::AsyncRuntime,
    simulation::{EgressComm, RequestSubscribeChannelPackets, StreamLookup, packet_state},
};

// TODO: Determine a better default
const DEFAULT_FRAGMENT_SIZE: usize = 4096;
const DEFAULT_PROXY_READ_BUFFER_SIZE: usize = 1024 * 1024;
const FRAME_LENGTH_PREFIX_SIZE: usize = size_of::<u64>();
const IROH_PROXY_REJECTED_CLOSE_CODE: u32 = 1;
const IROH_PROXY_REJECTED_REASON: &[u8] = b"unauthorized proxy";

#[derive(Debug, Clone, Default)]
pub struct IrohProxyBind {
    pub secret_key: Option<SecretKey>,
    pub bind_addr: Option<SocketAddr>,
    pub allowed_proxy_ids: Vec<PublicKey>,
}

#[derive(Resource, Debug, Clone)]
pub enum ProxyBind {
    Tcp(SocketAddr),
    Iroh(IrohProxyBind),
}

impl From<SocketAddr> for ProxyBind {
    fn from(value: SocketAddr) -> Self {
        Self::Tcp(value)
    }
}

fn proxy_id_is_allowed(allowed_proxy_ids: &[PublicKey], proxy_id: PublicKey) -> bool {
    allowed_proxy_ids.is_empty() || allowed_proxy_ids.contains(&proxy_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IROH_SECRET_KEY_BYTES: usize = 32;
    const ALLOWED_KEY_SEED: u8 = 1;
    const UNKNOWN_KEY_SEED: u8 = 2;

    fn public_key_from_seed(seed: u8) -> PublicKey {
        SecretKey::from([seed; IROH_SECRET_KEY_BYTES]).public()
    }

    #[test]
    fn empty_iroh_proxy_allowlist_accepts_any_peer() {
        let peer_id = public_key_from_seed(ALLOWED_KEY_SEED);

        assert!(proxy_id_is_allowed(&[], peer_id));
    }

    #[test]
    fn populated_iroh_proxy_allowlist_rejects_unknown_peer() {
        let allowed_id = public_key_from_seed(ALLOWED_KEY_SEED);
        let unknown_id = public_key_from_seed(UNKNOWN_KEY_SEED);

        assert!(!proxy_id_is_allowed(&[allowed_id], unknown_id));
    }
}

fn get_pid_from_port(port: u16) -> Result<Option<u32>, std::io::Error> {
    let output = if cfg!(target_os = "windows") {
        // todo: untested
        Command::new("cmd")
            .args(["/C", &format!("netstat -ano | findstr :{port}")])
            .output()?
    } else {
        Command::new("sh")
            .arg("-c")
            .arg(format!("lsof -i :{port} -t"))
            .output()?
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let pid = stdout.lines().next().and_then(|line| line.parse().ok());

    Ok(pid)
}

async fn handle_proxy_messages(
    read: impl AsyncRead + Unpin,
    command_channel: CommandChannel,
    proxy_id: ProxyId,
) {
    let mut reader = ProxyReader::new(read);
    let mut player_packet_sender: FxHashMap<u64, packet_channel::Sender> = FxHashMap::default();

    // Process packets
    loop {
        let buffer = match reader.next_server_packet_buffer().await {
            Ok(message) => message,
            Err(err) => {
                match err.downcast::<std::io::Error>() {
                    Ok(io_err) => match io_err.kind() {
                        std::io::ErrorKind::UnexpectedEof => {
                            warn!("proxy closed proxy to server connection");
                        }
                        kind => {
                            error!("closing proxy connection due to an i/o error: {kind}");
                        }
                    },
                    Err(err) => {
                        error!("closing proxy connection due to an unexpected error: {err:?}");
                    }
                }
                break;
            }
        };

        let result = unsafe { rkyv::access_unchecked::<ArchivedProxyToServerMessage<'_>>(buffer) };

        match result {
            ArchivedProxyToServerMessage::ProxyReady => {}
            ArchivedProxyToServerMessage::PlayerConnect(message) => {
                let Ok(stream) = rkyv::deserialize::<u64, !>(&message.stream);

                let (sender, receiver) = packet_channel::channel(DEFAULT_FRAGMENT_SIZE);
                if player_packet_sender.insert(stream, sender).is_some() {
                    error!(
                        "PlayerConnect: player with same stream id already exists in \
                         player_packet_sender"
                    );
                }

                command_channel.push(move |world: &mut World| {
                    let player = world
                        .spawn((
                            ConnectionId::new(stream, proxy_id),
                            packet_state::Handshake(()),
                            PacketDecoder::default(),
                            receiver,
                        ))
                        .id();
                    world
                        .get_resource_mut::<StreamLookup>()
                        .expect("StreamLookup resource should exist")
                        .insert(stream, player);
                });
            }
            ArchivedProxyToServerMessage::PlayerDisconnect(message) => {
                let Ok(stream) = rkyv::deserialize::<u64, !>(&message.stream);

                if player_packet_sender.remove(&stream).is_none() {
                    error!(
                        "PlayerDisconnect: no player with stream id exists in player_packet_sender"
                    );
                }

                command_channel.push(move |world: &mut World| {
                    let player = world
                        .get_resource_mut::<StreamLookup>()
                        .expect("StreamLookup resource should exist")
                        .remove(&stream)
                        .expect("player from PlayerDisconnect must exist in the stream lookup map");

                    world.despawn(player);
                });
            }
            ArchivedProxyToServerMessage::PlayerPackets(message) => {
                let Ok(stream) = rkyv::deserialize::<u64, !>(&message.stream);

                let Some(sender) = player_packet_sender.get_mut(&stream) else {
                    error!(
                        "PlayerPackets: no player with stream id exists in player_packet_sender"
                    );
                    continue;
                };

                if let Err(e) = sender.send(&message.data) {
                    use packet_channel::SendError;
                    let needs_shutdown = match e {
                        SendError::ZeroLengthPacket => {
                            warn!("A player sent an illegal zero-length packet, disconnecting");
                            true
                        }
                        SendError::TooLargePacket => {
                            warn!("A player sent a packet that is too large, disconnecting");
                            true
                        }
                        SendError::AlreadyClosed => false,
                    };
                    if needs_shutdown {
                        command_channel.push(move |world: &mut World| {
                            let compose = world
                                .get_resource::<Compose>()
                                .expect("Compose resource should exist");
                            compose
                                .io_buf()
                                .shutdown(ConnectionId::new(stream, proxy_id));
                        });
                    }
                }
            }
            ArchivedProxyToServerMessage::RequestSubscribeChannelPackets(message) => {
                let channels =
                    match rkyv::deserialize::<Box<[u32]>, rkyv::rancor::Error>(&message.channels) {
                        Ok(channels) => channels,
                        Err(e) => {
                            error!(
                                "RequestSubscribeChannelPackets: failed to deserialize channels: \
                                 {e}"
                            );
                            continue;
                        }
                    };

                command_channel.push(move |world: &mut World| {
                    // TODO: Is it possible to avoid this second allocation?
                    let channels = channels
                        .into_iter()
                        .filter_map(|channel_id| match Entity::from_id(channel_id, world) {
                            Ok(channel) => Some(RequestSubscribeChannelPackets(channel)),
                            Err(e) => {
                                error!(
                                    "RequestSubscribeChannelPackets: channel id is invalid: {e}"
                                );
                                None
                            }
                        })
                        .collect::<Vec<_>>();

                    let mut events = world.resource_mut::<Events<RequestSubscribeChannelPackets>>();
                    events.send_batch(channels);
                });
            }
        }
    }

    // Disconnect all players that were connected through this proxy
    command_channel.push(move |world: &mut World| {
        let mut query = world.query::<(Entity, &ConnectionId)>();
        let players_to_remove = query
            .iter(world)
            .filter(|(_, connection_id)| connection_id.proxy_id() == proxy_id)
            .map(|(entity, _)| entity)
            .collect::<Vec<_>>();
        for player in players_to_remove {
            world.despawn(player);
        }
    });
}

fn spawn_registered_proxy_connection<R, W>(
    read: R,
    mut write: W,
    command_channel: CommandChannel,
    next_proxy_id: Arc<AtomicU64>,
    peer_label: String,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let egress_comm = EgressComm::from(tx.clone());
    let proxy_id = ProxyId::new(next_proxy_id.fetch_add(1, Ordering::Relaxed));

    command_channel.push(move |world: &mut World| {
        let mut compose = world.resource_mut::<Compose>();
        compose.io_buf_mut().add_proxy(proxy_id, egress_comm);
    });

    let command_channel_clone = command_channel.clone();
    tokio::spawn(async move {
        // Send the bytes from the channel to the proxy
        while let Some(bytes) = rx.recv().await {
            if write.write_all(&bytes).await.is_err() {
                error!("error writing to proxy {peer_label}");
                break;
            }
        }

        warn!("proxy {peer_label} shut down");

        command_channel_clone.push(move |world: &mut World| {
            // Remove this channel from the compose egress comms list
            let mut compose = world.resource_mut::<Compose>();
            let removed = compose.io_buf_mut().remove_proxy(proxy_id).is_some();
            if !removed {
                error!("failed to remove proxy from compose egress comms");
            }

            // Explicitly close this receiver. This ensures that the channel isn't
            // closed before this, which would lead to an error on the sender side
            // of Compose.
            rx.close();
        });
    });

    command_channel.push(move |world: &mut World| {
        // Let the proxy know about all packet channels that exist at the moment

        let mut query = world.query_filtered::<Entity, With<Channel>>();
        let compose = world.resource::<Compose>();
        for channel in query.iter(world) {
            let packet = play::EntitiesDestroyS2c {
                entity_ids: vec![VarInt(channel.minecraft_id())].into(),
            };

            let packet_buf = compose.io_buf().encode_packet(&packet, compose).unwrap();

            tx.send(IoBuf::encode_proxy_message(
                &hyperion_proto::ServerToProxyMessage::AddChannel(hyperion_proto::AddChannel {
                    channel_id: ChannelId::from(channel).inner(),
                    unsubscribe_packets: &packet_buf,
                }),
            ))
            .unwrap();
        }
    });

    tokio::spawn(handle_proxy_messages(
        read,
        command_channel.clone(),
        proxy_id,
    ));
}

async fn inner_tcp(socket: SocketAddr, crypto: Crypto, command_channel: CommandChannel) {
    let listener = match tokio::net::TcpListener::bind(socket).await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            let error_msg = format!(
                "Failed to bind to address {socket}: Already in use. Is another process using \
                 this port?"
            );
            let port = socket.port();

            match get_pid_from_port(port) {
                Ok(Some(pid)) => {
                    let error_msg =
                        format!("{error_msg}\nAlready in use by process with PID {pid}");
                    panic!("{error_msg}");
                }
                Ok(None) => {
                    panic!("{error_msg} for port {port}");
                }
                Err(e) => {
                    let error_msg = format!("{error_msg}\n{e}");
                    panic!("{error_msg}");
                }
            }
        }
        Err(e) => panic!("Failed to bind to address {socket}: {e}"),
    };

    let root_cert_store = Arc::new(RootCertStore {
        roots: vec![
            webpki::anchor_from_trusted_cert(&crypto.root_ca_cert)
                .unwrap()
                .to_owned(),
        ],
    });

    let config = ServerConfig::builder()
        .with_client_cert_verifier(
            WebPkiClientVerifier::builder(root_cert_store)
                .build()
                .unwrap(),
        )
        .with_single_cert(vec![crypto.cert, crypto.root_ca_cert], crypto.key)
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(config));

    tokio::spawn(
        async move {
            let next_proxy_id = Arc::new(AtomicU64::new(0));

            loop {
                let (socket, _) = listener.accept().await.unwrap();

                socket.set_nodelay(true).unwrap();

                let addr = match socket.peer_addr() {
                    Ok(addr) => addr,
                    Err(e) => {
                        error!("failed to accept proxy connection: peer addr failed: {e}");
                        continue;
                    }
                };

                let command_channel = command_channel.clone();
                let next_proxy_id = next_proxy_id.clone();
                let stream = acceptor.accept(socket);

                tokio::spawn(async move {
                    let stream = match stream.await {
                        Ok(stream) => stream,
                        Err(e) => {
                            error!(
                                "failed to accept proxy connection from {addr}: tls accept \
                                 failed: {e}"
                            );
                            return;
                        }
                    };

                    info!("Proxy connection established on {addr}");

                    let (read, write) = tokio::io::split(stream);
                    spawn_registered_proxy_connection(
                        read,
                        write,
                        command_channel,
                        next_proxy_id,
                        addr.to_string(),
                    );
                });
            }
        }, // .instrument(info_span!("proxy reader")),
    );
}

async fn inner_iroh(config: IrohProxyBind, command_channel: CommandChannel) {
    let mut builder = IrohEndpoint::builder()
        .discovery_n0()
        .alpns(vec![IROH_PROXY_ALPN.to_vec()]);

    if let Some(secret_key) = config.secret_key.clone() {
        builder = builder.secret_key(secret_key);
    }

    if let Some(bind_addr) = config.bind_addr {
        builder = match bind_addr {
            SocketAddr::V4(addr) => builder.bind_addr_v4(addr),
            SocketAddr::V6(addr) => builder.bind_addr_v6(addr),
        };
    }

    let endpoint = match builder.bind().await {
        Ok(endpoint) => endpoint,
        Err(err) => {
            error!("failed to bind Iroh proxy endpoint: {err}");
            return;
        }
    };

    match endpoint.node_addr().await {
        Ok(addr) => info!(endpoint_addr = ?addr, "Iroh proxy listener started"),
        Err(error) => warn!(
            ?error,
            "Iroh proxy listener started without resolved address"
        ),
    }

    let next_proxy_id = Arc::new(AtomicU64::new(0));

    loop {
        let Some(connecting) = endpoint.accept().await else {
            warn!("Iroh proxy endpoint closed");
            break;
        };

        let allowed_proxy_ids = config.allowed_proxy_ids.clone();
        let command_channel = command_channel.clone();
        let next_proxy_id = next_proxy_id.clone();

        tokio::spawn(async move {
            let connection = match connecting.await {
                Ok(connection) => connection,
                Err(err) => {
                    error!("failed to accept Iroh proxy connection: {err}");
                    return;
                }
            };

            let remote_id = match connection.remote_node_id() {
                Ok(remote_id) => remote_id,
                Err(err) => {
                    error!("failed to read Iroh proxy remote id: {err}");
                    return;
                }
            };
            if !proxy_id_is_allowed(&allowed_proxy_ids, remote_id) {
                warn!(remote_id = %remote_id, "rejecting unauthorized Iroh proxy");
                connection.close(
                    IROH_PROXY_REJECTED_CLOSE_CODE.into(),
                    IROH_PROXY_REJECTED_REASON,
                );
                return;
            }

            let (write, read) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(err) => {
                    error!(remote_id = %remote_id, "failed to accept Iroh proxy stream: {err}");
                    return;
                }
            };

            info!(remote_id = %remote_id, "Iroh proxy stream established");
            spawn_registered_proxy_connection(
                read,
                write,
                command_channel,
                next_proxy_id,
                remote_id.to_string(),
            );
        });
    }
}

pub fn init_proxy_transport_comms(
    runtime: &AsyncRuntime,
    command_channel: CommandChannel,
    proxy_bind: ProxyBind,
    crypto: Option<Crypto>,
) {
    match proxy_bind {
        ProxyBind::Tcp(socket) => {
            let Some(crypto) = crypto else {
                error!("TCP proxy bind requires Crypto resource");
                return;
            };
            runtime.spawn(inner_tcp(socket, crypto, command_channel));
        }
        ProxyBind::Iroh(config) => {
            runtime.spawn(inner_iroh(config, command_channel));
        }
    }
}

/// Initializes proxy communications.
pub fn init_proxy_comms(
    runtime: &AsyncRuntime,
    command_channel: CommandChannel,
    socket: SocketAddr,
    crypto: Crypto,
) {
    runtime.spawn(inner_tcp(socket, crypto, command_channel));
}

#[derive(Debug)]
struct ProxyReader<R> {
    server_read: R,
    buffer: Vec<u8>,
}

impl<R> ProxyReader<R>
where
    R: AsyncRead + Unpin,
{
    pub fn new(server_read: R) -> Self {
        Self {
            server_read,
            buffer: vec![0; DEFAULT_PROXY_READ_BUFFER_SIZE],
        }
    }

    // #[instrument]
    pub async fn next_server_packet_buffer(&mut self) -> anyhow::Result<&[u8]> {
        let mut len = [0u8; FRAME_LENGTH_PREFIX_SIZE];
        self.server_read.read_exact(&mut len).await?;
        let len = u64::from_be_bytes(len);
        let len = usize::try_from(len)?;

        if len > self.buffer.len() {
            self.buffer.resize(len, 0);
        }

        let buffer = &mut self.buffer[..len];

        self.server_read.read_exact(buffer).await?;

        Ok(buffer)
    }
}
