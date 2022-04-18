use std::cmp::min;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, Result};
use smoltcp::Error;
use smoltcp::iface::{Interface, InterfaceBuilder, Routes, SocketHandle};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{Socket, TcpSocket, TcpSocketBuffer, TcpState};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket};
use tokio::sync::mpsc::{Permit, Receiver, Sender, UnboundedReceiver};
use tokio::sync::oneshot;

/// generic IP packet type that wraps both IPv4 and IPv6 packet buffers
#[derive(Debug)]
pub enum IpPacket {
    V4(Ipv4Packet<Vec<u8>>),
    V6(Ipv6Packet<Vec<u8>>),
}

impl From<Ipv4Packet<Vec<u8>>> for IpPacket {
    fn from(packet: Ipv4Packet<Vec<u8>>) -> Self {
        IpPacket::V4(packet)
    }
}

impl From<Ipv6Packet<Vec<u8>>> for IpPacket {
    fn from(packet: Ipv6Packet<Vec<u8>>) -> Self {
        IpPacket::V6(packet)
    }
}

impl TryFrom<Vec<u8>> for IpPacket {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(anyhow!("Empty packet."));
        }
        match value[0] >> 4 {
            4 => Ok(IpPacket::V4(Ipv4Packet::new_checked(value)?)),
            6 => Ok(IpPacket::V6(Ipv6Packet::new_checked(value)?)),
            _ => Err(anyhow!("Not an IP packet: {:?}", value)),
        }
    }
}

impl IpPacket {
    pub fn src_ip(&self) -> IpAddr {
        match self {
            IpPacket::V4(packet) => IpAddr::V4(Ipv4Addr::from(packet.src_addr())),
            IpPacket::V6(packet) => IpAddr::V6(Ipv6Addr::from(packet.src_addr())),
        }
    }

    pub fn dst_ip(&self) -> IpAddr {
        match self {
            IpPacket::V4(packet) => IpAddr::V4(Ipv4Addr::from(packet.dst_addr())),
            IpPacket::V6(packet) => IpAddr::V6(Ipv6Addr::from(packet.dst_addr())),
        }
    }

    pub fn transport_protocol(&self) -> IpProtocol {
        match self {
            IpPacket::V4(packet) => packet.protocol(),
            IpPacket::V6(packet) => {
                log::debug!("TODO: Implement IPv6 next_header logic.");
                packet.next_header()
            },
        }
    }

    pub fn transport_payload_mut(&mut self) -> &mut [u8] {
        match self {
            IpPacket::V4(packet) => packet.payload_mut(),
            IpPacket::V6(packet) => packet.payload_mut(),
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        match self {
            IpPacket::V4(packet) => packet.into_inner(),
            IpPacket::V6(packet) => packet.into_inner(),
        }
    }
}

#[derive(Debug)]
pub enum NetworkCommand {
    SendPacket(IpPacket),
}

#[derive(Debug)]
pub enum NetworkEvent {
    ReceivePacket(IpPacket),
}

pub type ConnectionId = u32;

#[derive(Debug)]
pub enum TransportEvent {
    ConnectionEstablished {
        connection_id: ConnectionId,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    },
    DatagramReceived {
        data: Vec<u8>,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    },
}

/// Commands that are sent by the Python side.
#[derive(Debug)]
pub enum TransportCommand {
    ReadData(ConnectionId, u32, oneshot::Sender<Vec<u8>>),
    WriteData(ConnectionId, Vec<u8>),
    DrainWriter(ConnectionId, oneshot::Sender<()>),
    CloseConnection(ConnectionId, bool),
    SendDatagram {
        data: Vec<u8>,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    },
}

pub struct VirtualDevice {
    rx_buffer: Vec<Vec<u8>>,
    tx_channel: Sender<NetworkCommand>,
}

impl VirtualDevice {
    pub fn new(tx_channel: Sender<NetworkCommand>) -> Self {
        VirtualDevice {
            rx_buffer: vec![],
            tx_channel,
        }
    }

    pub fn receive_packet(self: &mut Self, packet: IpPacket) {
        self.rx_buffer.push(packet.into_inner());
    }
}

impl<'a> Device<'a> for VirtualDevice {
    type RxToken = VirtualRxToken;
    type TxToken = VirtualTxToken<'a>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        match self.tx_channel.try_reserve() {
            Ok(permit) => {
                if let Some(buffer) = self.rx_buffer.pop() {
                    let rx = Self::RxToken { buffer };
                    let tx = VirtualTxToken(permit);
                    return Some((rx, tx));
                }
            },
            Err(_) => {},
        }
        None
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        match self.tx_channel.try_reserve() {
            Ok(permit) => Some(VirtualTxToken(permit)),
            Err(_) => None,
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1500;
        capabilities
    }
}

pub struct VirtualTxToken<'a>(Permit<'a, NetworkCommand>);

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        if result.is_ok() {
            self.0.send(NetworkCommand::SendPacket(
                IpPacket::try_from(buffer).map_err(|_| smoltcp::Error::Malformed)?,
            ));
        }
        result
    }
}

pub struct VirtualRxToken {
    buffer: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(&mut self.buffer[..])
    }
}

struct SocketData {
    handle: SocketHandle,
    send_buffer: VecDeque<u8>,
    write_eof: bool,
    recv_waiter: Option<(u32, oneshot::Sender<Vec<u8>>)>,
    drain_waiter: Vec<oneshot::Sender<()>>,
}

pub struct TcpServer<'a> {
    iface: Interface<'a, VirtualDevice>,
    net_tx: Sender<NetworkCommand>,
    net_rx: Receiver<NetworkEvent>,
    py_tx: Sender<TransportEvent>,
    py_rx: UnboundedReceiver<TransportCommand>,

    next_connection_id: ConnectionId,
    socket_data: HashMap<ConnectionId, SocketData>,
}

impl<'a> TcpServer<'a> {
    pub fn new(
        net_tx: Sender<NetworkCommand>,
        net_rx: Receiver<NetworkEvent>,
        py_tx: Sender<TransportEvent>,
        py_rx: UnboundedReceiver<TransportCommand>,
    ) -> Result<Self> {
        let device = VirtualDevice::new(net_tx.clone());

        let builder = InterfaceBuilder::new(device, vec![]);
        let ip_addrs = [IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0)];
        let mut routes = Routes::new(BTreeMap::new());
        // TODO: v6
        routes.add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1)).unwrap();

        let iface = builder.any_ip(true).ip_addrs(ip_addrs).routes(routes).finalize();

        Ok(Self {
            iface,
            net_tx,
            net_rx,
            py_tx,
            py_rx,
            next_connection_id: 0,
            socket_data: HashMap::new(),
        })
    }


    pub async fn receive_packet(&mut self, packet: IpPacket) -> Result<()> {
        match packet.transport_protocol() {
            IpProtocol::Tcp => self.receive_packet_tcp(packet).await,
            IpProtocol::Udp => self.receive_packet_udp(packet).await,
            _ => {
                log::debug!("Unhandled protocol: {}", packet.transport_protocol());
                return Ok(());
            }
        }
    }

    pub async fn receive_packet_udp(&mut self, mut packet: IpPacket) -> Result<()> {
        let src_ip = packet.src_ip();
        let dst_ip = packet.dst_ip();

        let mut udp_packet = match UdpPacket::new_checked(packet.transport_payload_mut()) {
            Ok(p) => p,
            Err(e) => {
                log::debug!("Invalid UDP packet: {}", e);
                return Ok(());
            },
        };
        let src_addr = SocketAddr::new(src_ip, udp_packet.src_port());
        let dst_addr = SocketAddr::new(dst_ip, udp_packet.dst_port());

        let event = TransportEvent::DatagramReceived {
                data: udp_packet.payload_mut().to_vec(),
                src_addr,
                dst_addr,
            };

        self.py_tx.send(event).await?;
        Ok(())
    }

    pub async fn receive_packet_tcp(&mut self, mut packet: IpPacket) -> Result<()> {

        let src_ip = packet.src_ip();
        let dst_ip = packet.dst_ip();

        let tcp_packet = match TcpPacket::new_checked(packet.transport_payload_mut()) {
            Ok(p) => p,
            Err(e) => {
                log::debug!("Invalid TCP packet: {}", e);
                return Ok(());
            },
        };

        let src_addr = SocketAddr::new(src_ip, tcp_packet.src_port());
        let dst_addr = SocketAddr::new(dst_ip, tcp_packet.dst_port());

        let syn = tcp_packet.syn();
        let _fin = tcp_packet.fin();

        if syn {
            let mut socket = TcpSocket::new(
                TcpSocketBuffer::new(vec![0u8; 64 * 1024]),
                TcpSocketBuffer::new(vec![0u8; 64 * 1024]),
            );
            socket.listen(dst_addr)?;
            socket.set_timeout(Some(Duration::from_secs(60)));
            socket.set_keep_alive(Some(Duration::from_secs(28)));
            let handle = self.iface.add_socket(socket);

            let connection_id = self.next_connection_id;
            self.next_connection_id += 1;

            let data = SocketData {
                handle,
                send_buffer: VecDeque::new(),
                write_eof: false,
                recv_waiter: None,
                drain_waiter: Vec::new(),
            };
            self.socket_data.insert(connection_id, data);

            self.py_tx
                .send(TransportEvent::ConnectionEstablished {
                    connection_id,
                    src_addr,
                    dst_addr,
                })
                .await?;
        }

        self.iface.device_mut().receive_packet(packet);

        Ok(())
    }

    pub fn read_data(&mut self, id: ConnectionId, n: u32, tx: oneshot::Sender<Vec<u8>>) {
        if let Some(data) = self.socket_data.get_mut(&id) {
            assert!(data.recv_waiter.is_none());
            data.recv_waiter = Some((n, tx));
        } else {
            // connection is has already been removed because the connection is closed,
            // so we just drop the tx.
        }
    }

    pub fn write_data(&mut self, id: ConnectionId, buf: Vec<u8>) {
        if let Some(data) = self.socket_data.get_mut(&id) {
            data.send_buffer.extend(buf);
        } else {
            // connection is has already been removed because the connection is closed,
            // so we just ignore the write.
        }
    }

    pub fn drain_writer(&mut self, id: ConnectionId, tx: oneshot::Sender<()>) {
        if let Some(data) = self.socket_data.get_mut(&id) {
            data.drain_waiter.push(tx);
        } else {
            // connection is has already been removed because the connection is closed,
            // so we just drop the tx.
        }
    }

    pub fn close_connection(&mut self, id: ConnectionId, half_close: bool) {
        if let Some(data) = self.socket_data.get_mut(&id) {
            let sock = self.iface.get_socket::<TcpSocket>(data.handle);
            if half_close {
                data.write_eof = true;
            } else {
                sock.abort();
            }
        } else {
            // connection is already dead.
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut remove_conns = Vec::new();

        loop {
            // On a high level, we do three things in our main loop:
            // 1. Wait for an event from either side and handle it, or wait until the next smoltcp timeout.
            // 2. `.poll()` the smoltcp interface until it's finished with everything for now.
            // 3. Check if we can wake up any waiters, move more data in the send buffer, or clean up sockets.

            let delay = self.iface.poll_delay(Instant::now());

            log::debug!("{:?}", &self);
            log::debug!("Poll: {:?}", &delay);

            tokio::select! {
                _ = async { tokio::time::sleep(delay.unwrap().into()).await }, if delay.is_some() => {},
                Some(e) = self.net_rx.recv() => {
                    match e {
                        NetworkEvent::ReceivePacket(packet) => {
                            self.receive_packet(packet).await?;
                        }
                    }
                },
                Some(e) = self.py_rx.recv() => {
                    match e {
                        TransportCommand::ReadData(id, n, tx) => {
                            self.read_data(id,n,tx);
                        },
                        TransportCommand::WriteData(id, buf) => {
                            self.write_data(id, buf);
                        },
                        TransportCommand::DrainWriter(id, tx) => {
                            self.drain_writer(id, tx);
                        },
                        TransportCommand::CloseConnection(id, half_close) => {
                            self.close_connection(id, half_close);
                        },
                        TransportCommand::SendDatagram{data: _, src_addr: _, dst_addr: _} => {
                            todo!();
                        },
                    }
                },
                Ok(()) = wait_for_channel_capacity(self.net_tx.clone()), if self.net_tx.capacity() == 0 => {
                    log::debug!("regained channel capacity");
                },
            }

            loop {
                match self.iface.poll(Instant::now()) {
                    Ok(_) => break,
                    Err(Error::Exhausted) => {
                        log::debug!("smoltcp: exhausted.");
                        break;
                    },
                    Err(e) => {
                        // these can happen for "normal" reasons such as invalid packets,
                        // we just write a log message and keep going.
                        log::debug!("smoltcp network error: {}", e)
                    },
                }
            }

            for (connection_id, data) in self.socket_data.iter_mut() {
                let sock = self.iface.get_socket::<TcpSocket>(data.handle);
                if data.recv_waiter.is_some() {
                    // dbg!(sock.state(), sock.can_recv(), sock.may_recv());
                    if sock.can_recv() {
                        let (n, tx) = data.recv_waiter.take().unwrap();
                        let bytes_available = sock.recv_queue();
                        let mut buf = vec![0u8; min(bytes_available, n as usize)];
                        let bytes_read = sock.recv_slice(&mut buf)?;
                        buf.truncate(bytes_read);
                        tx.send(buf).map_err(|_| anyhow!("cannot send read() bytes"))?;
                    } else {
                        // We can't use .may_recv() here as it returns false during establishment.
                        match sock.state() {
                            // can we still receive something in the future?
                            TcpState::CloseWait
                            | TcpState::LastAck
                            | TcpState::Closed
                            | TcpState::Closing
                            | TcpState::TimeWait => {
                                let (_, tx) = data.recv_waiter.take().unwrap();
                                tx.send(Vec::new()).map_err(|_| anyhow!("cannot send read() bytes"))?;
                            },
                            _ => {},
                        }
                    }
                }
                if !data.send_buffer.is_empty() {
                    if sock.can_send() {
                        let (a, b) = data.send_buffer.as_slices();
                        let sent = sock.send_slice(a)? + sock.send_slice(b)?;
                        data.send_buffer.drain(..sent);
                    }
                }
                if !data.drain_waiter.is_empty() {
                    if sock.send_queue() < sock.send_capacity() {
                        for waiter in data.drain_waiter.drain(..) {
                            waiter.send(()).map_err(|_| anyhow!("cannot notify drain writer"))?;
                        }
                    }
                }
                if data.send_buffer.is_empty() && data.write_eof {
                    // needs test: Is smoltcp smart enough to send out its own send buffer first?
                    sock.close();
                    data.write_eof = false;
                    continue; // we want one more poll() so that our FIN is sent.
                }
                if sock.state() == TcpState::Closed {
                    remove_conns.push(*connection_id);
                }
            }
            for connection_id in remove_conns.drain(..) {
                let data = self.socket_data.remove(&connection_id).unwrap();
                self.iface.remove_socket(data.handle);
            }
        }
    }
}

impl<'a> fmt::Debug for TcpServer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TcpServer {")?;
        f.debug_list()
            .entries(
                self.iface
                    .sockets()
                    .filter_map(|(_h, s)| match s {
                        Socket::Tcp(s) => Some(s),
                        _ => None,
                    })
                    .map(|sock| {
                        format!(
                            "TCP {:<21} {:<21} {}",
                            sock.remote_endpoint(),
                            sock.local_endpoint(),
                            sock.state()
                        )
                    }),
            )
            .finish()?;
        f.write_str("}")
    }
}

async fn wait_for_channel_capacity<T>(s: Sender<T>) -> Result<()> {
    let permit = s.reserve().await?;
    drop(permit);
    Ok(())
}
