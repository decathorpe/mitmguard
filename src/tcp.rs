use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;

use pretty_hex::pretty_hex;

use smoltcp::iface::{Interface, InterfaceBuilder, SocketHandle};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{Socket, TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Packet, TcpPacket};

use tokio::sync::{mpsc, RwLock};

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

    pub fn into_inner(self) -> Vec<u8> {
        match self {
            IpPacket::V4(packet) => packet.into_inner(),
            IpPacket::V6(packet) => packet.into_inner(),
        }
    }
}

pub struct TcpConnection {
    socket: SocketHandle,
    conn_back_send: mpsc::Sender<(SocketHandle, Vec<u8>)>,
    conn_forw_recv: mpsc::Receiver<Vec<u8>>,
}

impl TcpConnection {
    fn new(
        socket: SocketHandle,
        conn_back_send: mpsc::Sender<(SocketHandle, Vec<u8>)>,
        conn_forw_recv: mpsc::Receiver<Vec<u8>>,
    ) -> TcpConnection {
        TcpConnection {
            socket,
            conn_back_send,
            conn_forw_recv,
        }
    }

    pub async fn read(&mut self) -> Option<Vec<u8>> {
        self.conn_forw_recv.recv().await
    }

    pub async fn write(&mut self, data: Vec<u8>) {
        self.conn_back_send.send((self.socket, data)).await.unwrap()
    }
}

#[async_trait::async_trait]
pub trait ConnectionHandler: Send + Sync {
    async fn handle(&self, connection: TcpConnection);
}

pub struct PacketHandler {
    conn_handler: Arc<Box<dyn ConnectionHandler>>,
    iface: VirtualInterface,
    handles: HashMap<SocketAddr, SocketHandle>,
    connections: HashMap<SocketHandle, mpsc::Sender<Vec<u8>>>,
    memory: HashMap<SocketHandle, (IpAddr, IpAddr)>,

    // channels for sending IP packets to WireGuard peers
    ip_back_send: HashMap<u32, mpsc::Sender<IpPacket>>,

    // channel for receiving data from connection handlers
    conn_back_send: mpsc::Sender<(SocketHandle, Vec<u8>)>,
    conn_back_recv: Option<mpsc::Receiver<(SocketHandle, Vec<u8>)>>,
}

impl PacketHandler {
    pub fn new(conn_handler: Box<dyn ConnectionHandler>) -> PacketHandler {
        let (conn_back_send, conn_back_recv) = mpsc::channel(64);

        PacketHandler {
            conn_handler: Arc::new(conn_handler),
            iface: VirtualInterface::new(),
            handles: HashMap::new(),
            connections: HashMap::new(),
            memory: HashMap::new(),
            ip_back_send: HashMap::new(),
            conn_back_send,
            conn_back_recv: Some(conn_back_recv),
        }
    }

    pub fn add_peer(&mut self, idx: u32, ip_back_send: mpsc::Sender<IpPacket>) {
        self.ip_back_send.insert(idx, ip_back_send);
    }

    pub async fn handle(mut self, mut ip_forw_recv: mpsc::Receiver<(u32, IpPacket)>) -> Result<(), anyhow::Error> {
        let mut back_table: HashMap<IpAddr, u32> = HashMap::new();
        let mut conn_back_recv = self.conn_back_recv.take().unwrap();

        loop {
            tokio::select!(
                // handle IP packets that are received over the WireGuard tunnel
                ret = ip_forw_recv.recv() => {
                    if let Some((idx, packet)) = ret {
                        back_table.insert(packet.src_ip(), idx);

                        let resp_packets = self.recv(packet).await.unwrap();
                        for resp_packet in resp_packets {
                            self.ip_back_send.get(&idx).unwrap().send(resp_packet).await.unwrap();
                        }
                    }
                },
                _ = self.iface.ready() => {
                    // handle IP packets that are to be sent back over the WireGuard tunnel
                    if let Some(packet) = self.send().await.unwrap() {
                        if let Some(idx) = back_table.get(&packet.dst_ip()) {
                            let chan = self.ip_back_send.get(idx).unwrap();
                            chan.send(packet).await.unwrap();
                        } else {
                            log::debug!("Unknown destination address: {}", packet.dst_ip());
                        }
                    }
                },
                ret = conn_back_recv.recv() => {
                    if let Some((handle, data)) = ret {
                        let mut iface = self.iface.iface.write().await;
                        let socket: &mut TcpSocket = iface.get_socket(handle);
                        socket.send_slice(&data).unwrap();
                    }
                },
            );
        }
    }

    /// receive an IP packet from the WireGuard tunnel
    async fn recv(&mut self, ip_packet: IpPacket) -> Result<Vec<IpPacket>, anyhow::Error> {
        match ip_packet {
            IpPacket::V4(packet) => self.recv4(packet).await,
            IpPacket::V6(packet) => self.recv6(packet).await,
        }
    }

    /// receive an IPv4 packet from the WireGuard tunnel
    async fn recv4(&mut self, mut ip_packet: Ipv4Packet<Vec<u8>>) -> Result<Vec<IpPacket>, anyhow::Error> {
        if ip_packet.protocol() != IpProtocol::Tcp {
            log::warn!(
                "Attempt to send IP packet with unsupported protocol: {}",
                ip_packet.protocol()
            );
            return Ok(Vec::new());
        }

        let tcp_packet = TcpPacket::new_checked(ip_packet.payload_mut().to_vec()).context("invalid TCP packet")?;

        let src_ip = IpAddr::V4(Ipv4Addr::from(ip_packet.src_addr()));
        let dst_ip = IpAddr::V4(Ipv4Addr::from(ip_packet.dst_addr()));

        log::debug!("Outgoing IPv4 TCP packet: {} -> {}", src_ip, dst_ip);
        log::debug!("{}", pretty_hex(&ip_packet.payload_mut()));

        let dst_addr = SocketAddr::new(dst_ip, tcp_packet.dst_port());

        let syn = tcp_packet.syn();
        let fin = tcp_packet.fin();

        if syn {
            let mut socket = TcpSocket::new(
                TcpSocketBuffer::new(vec![0u8; 128 * 1024]),
                TcpSocketBuffer::new(vec![0u8; 128 * 1024]),
            );

            socket.set_ack_delay(None);
            socket.listen(dst_addr)?;

            let handle = self.iface.iface.write().await.add_socket(socket);
            self.handles.insert(dst_addr, handle);
            self.memory.insert(handle, (src_ip, dst_ip));

            // create connections with read / write streams for each new socket
            let (conn_forw_send, conn_forw_recv) = mpsc::channel(64);

            let connection = TcpConnection::new(handle, self.conn_back_send.clone(), conn_forw_recv);

            // spawn connection handler
            let conn_handler = self.conn_handler.clone();
            tokio::spawn(async move { conn_handler.handle(connection).await });

            // set up connection channels
            self.connections.insert(handle, conn_forw_send);
        }

        self.iface.recv_packet(ip_packet.into_inner().to_vec()).await;

        if fin {
            if let Some(handle) = self.handles.get(&dst_addr) {
                self.iface.iface.write().await.remove_socket(*handle);
            }
        }

        let mut responses: Vec<IpPacket> = Vec::new();
        while let Some(resp_packet) = self.iface.resp_packet().await {
            let packet = Ipv4Packet::new_checked(resp_packet)?;
            responses.push(packet.into());
        }

        Ok(responses)
    }

    /// receive an IPv6 packet from the WireGuard tunnel
    async fn recv6(&mut self, mut _ip_packet: Ipv6Packet<Vec<u8>>) -> Result<Vec<IpPacket>, anyhow::Error> {
        log::warn!("Sending IPv6 packets is not implemented yet.");
        Ok(Vec::new())
    }

    /// get an IP packet that should be sent through the WireGuard tunnel
    async fn send(&mut self) -> Result<Option<IpPacket>, anyhow::Error> {
        for (handle, socket) in self.iface.iface.write().await.sockets_mut() {
            match socket {
                Socket::Tcp(s) => {
                    if s.can_recv() {
                        let (dst_addr, src_addr) = self.memory.get(&handle).unwrap();

                        match (dst_addr, src_addr) {
                            (IpAddr::V4(dst_addr), IpAddr::V4(src_addr)) => {
                                let mut buf = [0u8; 1500];
                                let size = s.recv_slice(&mut buf).unwrap();

                                let packet = Self::send4(src_addr, dst_addr, &buf[..size])?;
                                return Ok(Some(packet.into()));
                            },
                            (IpAddr::V6(_dst_addr), IpAddr::V6(_src_addr)) => {
                                log::debug!("IPv6 packets not supported yet.");
                                // TODO: IPv6 support
                            },
                            _ => {
                                log::error!("Unsupported address pair: mixed IPv4 / IPv6");
                            },
                        }
                    }
                },
                _ => log::error!("Unsupported socket type: {:?}", socket),
            }
        }

        Ok(None)
    }

    /// construct an IPv4 TCP packet
    fn send4(src_addr: &Ipv4Addr, dst_addr: &Ipv4Addr, payload: &[u8]) -> Result<Ipv4Packet<Vec<u8>>, anyhow::Error> {
        // construct Ipv4 packet
        let repr = Ipv4Repr {
            src_addr: Ipv4Address::from(*src_addr),
            dst_addr: Ipv4Address::from(*dst_addr),
            protocol: IpProtocol::Tcp,
            payload_len: payload.len(),
            hop_limit: 64,
        };

        let buffer = vec![0u8; repr.buffer_len() + repr.payload_len];
        let mut ip_packet = Ipv4Packet::new_unchecked(buffer);

        // construct IP packet
        repr.emit(&mut ip_packet, &ChecksumCapabilities::default());
        // fill packet payload
        ip_packet.payload_mut().copy_from_slice(payload);

        ip_packet.fill_checksum();
        ip_packet.check_len()?;

        Ok(ip_packet)
    }
}

struct VirtualInterface {
    iface: Arc<RwLock<Interface<'static, VirtualDevice>>>,
}

impl VirtualInterface {
    /// construct a new virtual TCP interface
    fn new() -> VirtualInterface {
        let device = VirtualDevice::default();
        let builder = InterfaceBuilder::new(device, Vec::new());
        let iface = builder.any_ip(true).finalize();

        VirtualInterface {
            iface: Arc::new(RwLock::new(iface)),
        }
    }

    /// add a received packet
    async fn recv_packet(&mut self, packet: Vec<u8>) {
        self.iface.write().await.device_mut().recv_packet(packet)
    }

    /// get a response packet
    async fn resp_packet(&mut self) -> Option<Vec<u8>> {
        self.iface.write().await.device_mut().resp_packet()
    }

    async fn poll(&self, timestamp: Instant) -> smoltcp::Result<bool> {
        self.iface.write().await.poll(timestamp)
    }

    async fn wait(&self) {
        if let Some(dur) = self.iface.write().await.poll_delay(Instant::now()) {
            log::debug!("TCP poll delay: {}", dur);
            tokio::time::sleep(dur.into()).await;
        } else {
            // FIXME: Interface::poll_delay seems to always (?) return `None`.
            //        This statement was only added to avoid busy sleeping in this case.
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    pub async fn ready(&self) {
        loop {
            if let Ok(true) = self.poll(Instant::now()).await {
                return;
            } else {
                self.wait().await
            }
        }
    }
}

#[derive(Debug, Default)]
struct VirtualDevice {
    rx_buffer: VecDeque<Vec<u8>>,
    tx_buffer: VecDeque<Vec<u8>>,
}

impl VirtualDevice {
    pub fn recv_packet(&mut self, packet: Vec<u8>) {
        self.rx_buffer.push_back(packet);
    }

    pub fn resp_packet(&mut self) -> Option<Vec<u8>> {
        self.tx_buffer.pop_front()
    }
}

#[derive(Debug)]
struct VirtualRxToken {
    buffer: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(&mut self.buffer)
    }
}

#[derive(Debug)]
struct VirtualTxToken<'a> {
    device: &'a mut VirtualDevice,
}

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.device.tx_buffer.push_back(buffer);
        result
    }
}

impl<'a> Device<'a> for VirtualDevice {
    type RxToken = VirtualRxToken;
    type TxToken = VirtualTxToken<'a>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        if let Some(buffer) = self.rx_buffer.pop_front() {
            let rx = Self::RxToken { buffer };
            let tx = Self::TxToken { device: self };
            Some((rx, tx))
        } else {
            None
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(VirtualTxToken { device: self })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}
