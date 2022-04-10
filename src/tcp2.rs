use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, Context, Result};
use smoltcp::iface::{Interface, InterfaceBuilder, Routes, SocketHandle};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::time;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet, TcpPacket};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Permit, Receiver, Sender};
use tokio::sync::oneshot;

use crate::{py_events, ConnectionClosed, ConnectionEstablished, DatagramReceived, ConnectionCommand, ConnectionId};

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
    fn consume<R, F>(self, timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        if result.is_ok() {
            self.0.send(NetworkCommand::SendPacket(
                IpPacket::try_from(buffer).map_err(|e| smoltcp::Error::Malformed)?,
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


pub struct TcpServer<'a> {
    iface: Interface<'a, VirtualDevice>,
    net_rx: Receiver<NetworkEvent>,
    py_tx: Sender<py_events::Events>,
    py_rx: Receiver<py_events::ConnectionCommand>,
}

impl<'a> TcpServer<'a> {
    pub fn new(
        net_tx: Sender<NetworkCommand>,
        net_rx: Receiver<NetworkEvent>,
        py_tx: Sender<py_events::Events>,
        py_rx: Receiver<py_events::ConnectionCommand>,
    ) -> Result<Self> {
        let device = VirtualDevice::new(net_tx);

        let builder = InterfaceBuilder::new(device, vec![]);
        let ip_addrs = [IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0)];
        let mut routes = Routes::new(BTreeMap::new());
        // TODO: v6
        routes.add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1)).unwrap();

        let mut iface = builder.any_ip(true).ip_addrs(ip_addrs).routes(routes).finalize();


        Ok(Self {
            iface,
            net_rx,
            py_tx,
            py_rx,
        })
    }

    pub async fn receive_packet(&mut self, mut packet: IpPacket) -> Result<()> {
        if packet.transport_protocol() != IpProtocol::Tcp {
            log::debug!("Unhandled protocol: {}", packet.transport_protocol());
            return Ok(());
        }

        let src_ip = packet.src_ip();
        let dst_ip = packet.dst_ip();

        let tcp_packet = TcpPacket::new_checked(packet.transport_payload_mut()).context("invalid TCP packet")?;

        let src_addr = SocketAddr::new(src_ip, tcp_packet.src_port());
        let dst_addr = SocketAddr::new(dst_ip, tcp_packet.dst_port());

        let syn = tcp_packet.syn();
        let fin = tcp_packet.fin();

        if syn {
            let mut socket = TcpSocket::new(
                TcpSocketBuffer::new(vec![0u8; 128 * 1024]),
                TcpSocketBuffer::new(vec![0u8; 128 * 1024]),
            );
            socket.set_timeout(Some(Duration::from_secs(60)));
            socket.set_keep_alive(Some(Duration::from_secs(60)));
            socket.listen(dst_addr)?;
            self.iface.add_socket(socket);
            self.py_tx
                .send(py_events::Events::ConnectionEstablished(ConnectionEstablished {
                    connection_id: 42,
                    src_addr: src_addr.into(),
                    dst_addr: dst_addr.into(),
                }))
                .await?;
        } else {
            // TODO: Get socket.
        }

        if Ok(true) = self.iface.poll(Instant::now()) {
            // TODO: update socket waiter.
        }



        self.iface.device_mut().receive_packet(packet);

        Ok(())
    }

    pub async fn read_data(&mut self, id: ConnectionId, n: u32, tx: oneshot::Sender<Vec<u8>>) -> Result<()> {

        // FIXME: actually get correct socket.
        let sh = self.iface.sockets().next().unwrap().0;

        let sock = self.iface.get_socket::<TcpSocket>(sh);

        // FIXME handle n
        if sock.can_recv() {
            sock.recv(|data| {
                let len = data.len();
                match tx.send(Vec::from(data)) {
                    Ok(()) => (len, Ok(())),
                    Err(e) => (0, Err(e))
                }
            })?;
        } else {
            // FIXME: We should register a callback thingy here

            tx.send(vec![]);
        }

        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            let delay = self
                .iface
                .poll_delay(Instant::now())
                .unwrap_or_else(|| Duration::from_secs(10));

            let sleep = tokio::time::sleep(delay.into());
            tokio::pin!(sleep);

            tokio::select! {
                Some(e) = self.net_rx.recv() => {
                    match e {
                        NetworkEvent::ReceivePacket(packet) => {
                            self.receive_packet(packet).await?;
                        }
                    }
                },
                Some(e) = self.py_rx.recv() => {
                    match e {
                        ConnectionCommand::ReadData(id,n,tx) => {
                            self.read_data(id,n,tx).await?;
                        },
                        _ => {
                            todo!("Unimplemented: {:?}", e);
                        }
                    }
                },
                _ = &mut sleep => {}
            }

            match self.iface.poll(Instant::now()) {
                Ok(b) => {},
                Err(e) => {
                    log::debug!("smoltcp network error: {}", e)
                },
            }
        }
    }
}
