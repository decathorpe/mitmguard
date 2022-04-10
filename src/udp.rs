use std::net::SocketAddr;

use anyhow::Result;
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::mpsc::{Receiver, Sender};

pub struct UdpServer {
    tx: Sender<UdpEvent>,
    rx: Receiver<UdpCommand>,
    socket: UdpSocket,
}


#[derive(Debug)]
pub enum UdpCommand {
    SendDatagram(Vec<u8>, SocketAddr),
}

#[derive(Debug)]
pub enum UdpEvent {
    ReceiveDatagram(Vec<u8>, SocketAddr),
}


impl UdpServer {
    pub async fn new<A: ToSocketAddrs>(addr: A, tx: Sender<UdpEvent>, rx: Receiver<UdpCommand>) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self { rx, tx, socket })
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut buf = [0; 1500];

        loop {
            tokio::select! {
                Some(e) = self.rx.recv() => {
                    match e {
                        UdpCommand::SendDatagram(data, target) => {
                            self.socket.send_to(&data, target).await?;
                        }
                    }
                },
                ret = self.socket.recv_from(&mut buf) => {
                    let (len, addr) = ret.unwrap();
                    let data = Vec::from(&buf[..len]);
                    match self.tx.try_send(UdpEvent::ReceiveDatagram(data, addr)) {
                        Ok(()) => {},
                        Err(_) => {
                            log::warn!("Dropping incoming packet, WG channel is full.")
                        }
                    }
                }
            }
        }
    }
}
