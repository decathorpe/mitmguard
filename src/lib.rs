mod py_events;
mod tcp2;
mod udp;
mod wg2;


use std::sync::Arc;



use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tokio::sync::oneshot;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{channel, unbounded_channel};
use tokio::task::JoinHandle;

use anyhow::{anyhow, Result, Context};
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use py_events::*;


#[pyclass]
struct WireguardServer {
    event_tx: mpsc::UnboundedSender<ConnectionCommand>,
    python_callback_task: JoinHandle<()>,
}

#[pymethods]
impl WireguardServer {
    fn tcp_read<'p>(&self, py: Python<'p>, connection_id: ConnectionId, n: u32) -> PyResult<&'p PyAny> {
        let (tx, rx) = oneshot::channel();
        self.event_tx.send(ConnectionCommand::ReadData(connection_id, n, tx)).context("py -> smol event queue unavailable")?;
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let data = rx.await.context("failed to tcp_read()")?;
            let bytes: Py<PyBytes> = Python::with_gil(|py| {
                PyBytes::new(py, &data).into_py(py)
            });
            Ok(bytes)
        })
    }

    fn tcp_write(&self, connection_id: ConnectionId, data: Vec<u8>) -> PyResult<()> {
        self.event_tx.send(
            ConnectionCommand::WriteData(connection_id, data)
        ).context("py -> smol event queue unavailable")?;
        Ok(())
    }

    fn tcp_drain<'p>(&self, py: Python<'p>, connection_id: ConnectionId) -> PyResult<&'p PyAny> {
        let (tx, rx) = oneshot::channel();
        self.event_tx.send(ConnectionCommand::DrainWriter(connection_id, tx)).context("py -> smol event queue unavailable")?;
        pyo3_asyncio::tokio::future_into_py(py, async move {
            rx.await.context("failed to tcp_drain()")?;
            Ok(())
        })
    }

    #[args(half_close=false)]
    fn tcp_close(&self, connection_id: ConnectionId, half_close: bool) -> PyResult<()> {
        self.event_tx.send(
            ConnectionCommand::CloseConnection(connection_id, half_close)
        ).context("py -> smol event queue unavailable")?;
        Ok(())
    }

    fn stop(&self) -> PyResult<()> {
        self._stop();
        Ok(())
    }
}

impl WireguardServer {
    pub async fn new(on_event: PyObject) -> Result<WireguardServer> {

        /*
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .init();

        console_subscriber::init();
        */

        let server_priv_key: X25519SecretKey = "c72d788fd0916b1185177fd7fa392451192773c889d17ac739571a63482c18bb"
            .parse()
            .map_err(|error: &str| anyhow!(error))?;
        let peer_pub_key: X25519PublicKey = "DbwqnNYZWk5e19uuSR6WomO7VPaVbk/uKhmyFEnXdH8="
            .parse()
            .map_err(|error: &str| anyhow!(error))?;


        let (udp_to_wg_tx, udp_to_wg_rx) = channel(16);
        let (wg_to_udp_tx, wg_to_udp_rx) = channel(16);

        let (wg_to_smol_tx, wg_to_smol_rx) = channel(16);
        let (smol_to_wg_tx, smol_to_wg_rx) = channel(16);


        let (smol_to_py_tx, mut smol_to_py_rx) = channel(64); // only used to notify of incoming connections and datagrams:
        // used to send data and to ask for packets. We need this to be unbounded as write() is not async.
        let (py_to_smol_tx, py_to_smol_rx) = unbounded_channel();

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
fn start_server(py: Python<'_>, _host: String, _port: u16, on_event: PyObject) -> PyResult<&PyAny> {
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
    m.add_class::<DatagramReceived>()?;
    Ok(())
}
