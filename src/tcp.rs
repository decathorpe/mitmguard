use std::cmp::min;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use smoltcp::iface::{Interface, InterfaceBuilder, Routes, SocketHandle};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::{Socket, TcpSocket, TcpSocketBuffer, TcpState};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{
    IpAddress, IpCidr, IpProtocol, IpRepr, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet, Ipv6Repr,
    TcpPacket, UdpPacket, UdpRepr,
};
use smoltcp::Error;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver};
use tokio::sync::oneshot;

use crate::messages::{ConnectionId, IpPacket, NetworkCommand, NetworkEvent, TransportCommand, TransportEvent};
use crate::virtual_device::VirtualDevice;

/// Associated data for a smoltcp socket.
struct SocketData {
    handle: SocketHandle,
    /// smoltcp can only operate with fixed-size buffers, but Python's stream implementation assumes
    /// an infinite buffer. So we have a second send buffer here, plus a boolean to indicate that
    /// we want to send a FIN.
    send_buffer: VecDeque<u8>,
    write_eof: bool,
    // Gets notified once there's data to be read.
    recv_waiter: Option<(u32, oneshot::Sender<Vec<u8>>)>,
    // Gets notified once there is enough space in the write buffer.
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
                        TransportCommand::SendDatagram{data, src_addr, dst_addr} => {
                            self.send_datagram(data, src_addr, dst_addr);
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
                    // TODO: benchmark different variants here. (e.g. only return on half capacity)
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
                    continue; // we want one more poll() so that our FIN is sent (TODO: test that).
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

    async fn receive_packet(&mut self, packet: IpPacket) -> Result<()> {
        match packet.transport_protocol() {
            IpProtocol::Tcp => self.receive_packet_tcp(packet).await,
            IpProtocol::Udp => self.receive_packet_udp(packet).await,
            _ => {
                log::debug!("Unhandled protocol: {}", packet.transport_protocol());
                return Ok(());
            },
        }
    }

    async fn receive_packet_udp(&mut self, mut packet: IpPacket) -> Result<()> {
        let src_ip = packet.src_ip();
        let dst_ip = packet.dst_ip();

        let mut udp_packet = match UdpPacket::new_checked(packet.payload_mut()) {
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

    async fn receive_packet_tcp(&mut self, mut packet: IpPacket) -> Result<()> {
        let src_ip = packet.src_ip();
        let dst_ip = packet.dst_ip();

        let tcp_packet = match TcpPacket::new_checked(packet.payload_mut()) {
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

    fn read_data(&mut self, id: ConnectionId, n: u32, tx: oneshot::Sender<Vec<u8>>) {
        if let Some(data) = self.socket_data.get_mut(&id) {
            assert!(data.recv_waiter.is_none());
            data.recv_waiter = Some((n, tx));
        } else {
            // connection is has already been removed because the connection is closed,
            // so we just drop the tx.
        }
    }

    fn write_data(&mut self, id: ConnectionId, buf: Vec<u8>) {
        if let Some(data) = self.socket_data.get_mut(&id) {
            data.send_buffer.extend(buf);
        } else {
            // connection is has already been removed because the connection is closed,
            // so we just ignore the write.
        }
    }

    fn drain_writer(&mut self, id: ConnectionId, tx: oneshot::Sender<()>) {
        if let Some(data) = self.socket_data.get_mut(&id) {
            data.drain_waiter.push(tx);
        } else {
            // connection is has already been removed because the connection is closed,
            // so we just drop the tx.
        }
    }

    fn close_connection(&mut self, id: ConnectionId, half_close: bool) {
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

    fn send_datagram(&mut self, data: Vec<u8>, src_addr: SocketAddr, dst_addr: SocketAddr) {
        let permit = match self.net_tx.try_reserve() {
            Ok(p) => p,
            Err(_) => {
                log::debug!("Channel full, discarding UDP packet.");
                return;
            },
        };

        // We now know that there's space for us to send,
        // let's painstakingly reassemble the IP packet...

        let udp_repr = UdpRepr {
            src_port: src_addr.port(),
            dst_port: dst_addr.port(),
        };

        let ip_repr: IpRepr = match (src_addr, dst_addr) {
            (SocketAddr::V4(src_addr), SocketAddr::V4(dst_addr)) => IpRepr::Ipv4(Ipv4Repr {
                src_addr: Ipv4Address::from(*src_addr.ip()),
                dst_addr: Ipv4Address::from(*dst_addr.ip()),
                protocol: IpProtocol::Udp,
                payload_len: udp_repr.header_len() + data.len(),
                hop_limit: 255,
            }),
            (SocketAddr::V6(src_addr), SocketAddr::V6(dst_addr)) => IpRepr::Ipv6(Ipv6Repr {
                src_addr: Ipv6Address::from(*src_addr.ip()),
                dst_addr: Ipv6Address::from(*dst_addr.ip()),
                next_header: IpProtocol::Udp,
                payload_len: udp_repr.header_len() + data.len(),
                hop_limit: 255,
            }),
            _ => {
                log::error!("A datagram's src_addr and dst_addr must agree on IP version.");
                return;
            },
        };

        let buf = vec![0u8; ip_repr.total_len()];

        let mut ip_packet = match ip_repr {
            IpRepr::Ipv4(repr) => {
                let mut packet = Ipv4Packet::new_unchecked(buf);
                repr.emit(&mut packet, &ChecksumCapabilities::default());
                IpPacket::from(packet)
            },
            IpRepr::Ipv6(repr) => {
                let mut packet = Ipv6Packet::new_unchecked(buf);
                repr.emit(&mut packet);
                IpPacket::from(packet)
            },
            _ => unreachable!(),
        };

        udp_repr.emit(
            &mut UdpPacket::new_unchecked(ip_packet.payload_mut()),
            &ip_repr.src_addr(),
            &ip_repr.dst_addr(),
            data.len(),
            |buf| buf.copy_from_slice(data.as_slice()),
            &ChecksumCapabilities::default(),
        );

        permit.send(NetworkCommand::SendPacket(ip_packet));
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
