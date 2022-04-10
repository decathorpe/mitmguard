mod py_events;
mod tcp2;
mod udp;
mod wg2;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::udp::UdpServer;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tokio::sync::oneshot;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{channel, unbounded_channel};
use tokio::task::JoinHandle;

use anyhow::{anyhow, Result};
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use py_events::*;


#[pyclass]
struct WireguardServer {
    event_tx: mpsc::Sender<ConnectionCommand>,
    python_callback_task: JoinHandle<()>,
}

async fn read(connection_id: ConnectionId, n: u32, event_tx: mpsc::Sender<ConnectionCommand>) -> Result<Vec<u8>> {
    let (tx, rx) = oneshot::channel();
    event_tx.send(ConnectionCommand::ReadData(connection_id, n, tx)).await?;
    let data = rx.await?;
    Ok(data)
}


#[pymethods]
impl WireguardServer {
    fn tcp_read<'p>(&self, py: Python<'p>, connection_id: ConnectionId, n: u32) -> PyResult<&'p PyAny> {
        let event_tx = self.event_tx.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let data = read(connection_id, n, event_tx).await?;
            Ok(data)
        })
    }

    fn tcp_send(&self, connection_id: ConnectionId, data: Vec<u8>) -> PyResult<()> {
        todo!()
    }

    fn tcp_close(&self, connection_id: ConnectionId) -> PyResult<()> {
        todo!()
    }

    fn stop(&self) -> PyResult<()> {
        self._stop();
        Ok(())
    }
}

impl WireguardServer {
    pub async fn new(on_event: PyObject) -> Result<WireguardServer> {
        let server_priv_key: X25519SecretKey = "c72d788fd0916b1185177fd7fa392451192773c889d17ac739571a63482c18bb"
            .parse()
            .map_err(|error: &str| anyhow!(error))?;
        let peer_pub_key: X25519PublicKey = "DbwqnNYZWk5e19uuSR6WomO7VPaVbk/uKhmyFEnXdH8="
            .parse()
            .map_err(|error: &str| anyhow!(error))?;


        let (udp_to_wg_tx, udp_to_wg_rx) = channel(16);
        let (wg_to_udp_tx, wg_to_udp_rx) = channel(16);

        let (wg_to_smol_tx, mut wg_to_smol_rx) = channel(16);
        let (smol_to_wg_tx, smol_to_wg_rx) = channel(16);


        let (smol_to_py_tx, mut smol_to_py_rx) = channel(64); // only used to notify of incoming connections and datagrams:
        let (py_to_smol_tx, mut py_to_smol_rx) = channel(64); // used to send data and to ask for packets.

        let mut udp_server = udp::UdpServer::new("0.0.0.0:51820", udp_to_wg_tx, wg_to_udp_rx).await?;

        let mut wg_server = wg2::WgServer::new(
            Arc::new(server_priv_key),
            vec![(Arc::new(peer_pub_key), None)],
            wg_to_udp_tx,
            udp_to_wg_rx,
            wg_to_smol_tx,
            smol_to_wg_rx,
        )?;

        let mut tcp_server = tcp2::TcpServer::new(smol_to_wg_tx, wg_to_smol_rx, smol_to_py_tx, py_to_smol_rx)?;

        // TODO: store handles and abort later.
        tokio::spawn(async move { udp_server.run().await });
        tokio::spawn(async move { wg_server.run().await });
        tokio::spawn(async move { tcp_server.run().await });

        // this task feeds events into the Python callback.
        let python_callback_task = tokio::spawn(async move {
            while let Some(event) = smol_to_py_rx.recv().await {
                Python::with_gil(|py| {
                    if let Err(err) = on_event.call1(py, (event,)) {
                        err.print(py);
                    }
                });
            }
        });

        Ok(WireguardServer { python_callback_task, event_tx: py_to_smol_tx })
    }
    fn _stop(&self) {
        self.python_callback_task.abort();
        // TODO: this is not trivial. we should close all connections somehow.
    }
}

impl Drop for WireguardServer {
    fn drop(&mut self) {
        self._stop();
    }
}

#[pyfunction]
fn start_server(py: Python<'_>, host: String, port: u16, on_event: PyObject) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        // TODO: We need to split this into bind() and start().
        //  Otherwise there's a nasty race where on_event is called before start_server has been awaited.
        let server = WireguardServer::new(on_event).await?;
        Ok(server)
    })
}

#[pymodule]
fn mitmproxy_wireguard(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(start_server, m)?)?;
    m.add_class::<ConnectionEstablished>()?;
    m.add_class::<ConnectionClosed>()?;
    m.add_class::<DatagramReceived>()?;
    Ok(())
}
