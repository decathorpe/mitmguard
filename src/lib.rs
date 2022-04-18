use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use pyo3::exceptions::{PyKeyError, PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString, PyTuple};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{channel, unbounded_channel};
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::RecvError;
use tokio::task::JoinHandle;

use py_events::*;
use tcp::{ConnectionId, TransportCommand, TransportEvent};

mod py_events;
mod tcp;
mod wireguard;

#[pyclass]
struct TcpStream {
    connection_id: ConnectionId,
    event_tx: mpsc::UnboundedSender<TransportCommand>,
    peername: SocketAddr,
    sockname: SocketAddr,
    original_dst: SocketAddr,
}

#[pymethods]
impl TcpStream {
    fn read<'p>(&self, py: Python<'p>, n: u32) -> PyResult<&'p PyAny> {
        let (tx, rx) = oneshot::channel();
        self.event_tx
            .send(TransportCommand::ReadData(self.connection_id, n, tx))
            .map_err(event_queue_unavailable)?;
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let data = rx.await.map_err(connection_closed)?;
            let bytes: Py<PyBytes> = Python::with_gil(|py| PyBytes::new(py, &data).into_py(py));
            Ok(bytes)
        })
    }

    fn write(&self, data: Vec<u8>) -> PyResult<()> {
        self.event_tx
            .send(TransportCommand::WriteData(self.connection_id, data))
            .map_err(event_queue_unavailable)?;
        Ok(())
    }

    fn drain<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        let (tx, rx) = oneshot::channel();
        self.event_tx
            .send(TransportCommand::DrainWriter(self.connection_id, tx))
            .map_err(event_queue_unavailable)?;
        pyo3_asyncio::tokio::future_into_py(py, async move {
            rx.await.map_err(connection_closed)?;
            Ok(())
        })
    }

    fn write_eof(&self) -> PyResult<()> {
        self.event_tx
            .send(TransportCommand::CloseConnection(self.connection_id, true))
            .map_err(event_queue_unavailable)?;
        Ok(())
    }

    fn close(&self) -> PyResult<()> {
        self.event_tx
            .send(TransportCommand::CloseConnection(self.connection_id, false))
            .map_err(event_queue_unavailable)?;
        Ok(())
    }

    fn get_extra_info(&self, py: Python, name: String) -> PyResult<PyObject> {
        match name.as_str() {
            "peername" => Ok(socketaddr_to_py(py, self.peername)),
            "sockname" => Ok(socketaddr_to_py(py, self.sockname)),
            "original_dst" => Ok(socketaddr_to_py(py, self.original_dst)),
            _ => Err(PyKeyError::new_err(name)),
        }
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.close().ok();
    }
}

fn socketaddr_to_py(py: Python, s: SocketAddr) -> PyObject {
    match s {
        SocketAddr::V4(addr) => (addr.ip().to_string(), addr.port()).into_py(py),
        SocketAddr::V6(addr) => {
            log::debug!(
                "converting ipv6 to python, not sure if this is correct: {:?}",
                (addr.ip().to_string(), addr.port())
            );
            (addr.ip().to_string(), addr.port()).into_py(py)
        },
    }
}

fn py_to_socketaddr(t: &PyTuple) -> PyResult<SocketAddr> {
    if t.len() == 2 {
        let host = t.get_item(0)?.downcast::<PyString>()?;
        let port: u16 = t.get_item(1)?.extract()?;
        let addr = IpAddr::from_str(host.to_str()?)?;
        Ok(SocketAddr::from((addr, port)))
    } else {
        Err(PyValueError::new_err("not a socket address"))
    }
}

fn event_queue_unavailable(_: SendError<TransportCommand>) -> PyErr {
    PyOSError::new_err("py -> smol event queue unavailable")
}

fn connection_closed(_: RecvError) -> PyErr {
    PyOSError::new_err("connection closed")
}

#[pyclass]
struct WireguardServer {
    event_tx: mpsc::UnboundedSender<TransportCommand>,
    python_callback_task: JoinHandle<()>,
}

#[pymethods]
impl WireguardServer {
    fn send_datagram(&self, data: Vec<u8>, src_addr: &PyTuple, dst_addr: &PyTuple) -> PyResult<()> {
        self.event_tx
            .send(TransportCommand::SendDatagram {
                data,
                src_addr: py_to_socketaddr(src_addr)?,
                dst_addr: py_to_socketaddr(dst_addr)?,
            })
            .map_err(event_queue_unavailable)?;
        Ok(())
    }

    fn stop(&self) -> PyResult<()> {
        self._stop();
        Ok(())
    }
}

impl WireguardServer {
    pub async fn new(handler: PyObject) -> Result<WireguardServer> {
        let server_priv_key: X25519SecretKey = "c72d788fd0916b1185177fd7fa392451192773c889d17ac739571a63482c18bb"
            .parse()
            .map_err(|error: &str| anyhow!(error))?;
        let peer_pub_key: X25519PublicKey = "DbwqnNYZWk5e19uuSR6WomO7VPaVbk/uKhmyFEnXdH8="
            .parse()
            .map_err(|error: &str| anyhow!(error))?;

        let (wg_to_smol_tx, wg_to_smol_rx) = channel(16);
        let (smol_to_wg_tx, smol_to_wg_rx) = channel(16);

        let (smol_to_py_tx, mut smol_to_py_rx) = channel(64); // only used to notify of incoming connections and datagrams:
                                                              // used to send data and to ask for packets. We need this to be unbounded as write() is not async.
        let (py_to_smol_tx, py_to_smol_rx) = unbounded_channel();

        let mut wg_server = wireguard::WireguardServer::new(
            "0.0.0.0:51820",
            Arc::new(server_priv_key),
            vec![(Arc::new(peer_pub_key), None)],
            wg_to_smol_tx,
            smol_to_wg_rx,
        )
        .await?;
        let sockname = wg_server.socket.local_addr()?;

        let mut tcp_server = tcp::TcpServer::new(smol_to_wg_tx, wg_to_smol_rx, smol_to_py_tx, py_to_smol_rx)?;

        // TODO: store handles and abort later.
        tokio::spawn(async move { wg_server.run().await });
        tokio::spawn(async move { tcp_server.run().await });

        // this task feeds events into the Python callback.
        let event_tx = py_to_smol_tx.clone();

        let (py_loop, run_coroutine_threadsafe, handle_connection, receive_datagram) =
            Python::with_gil(|py| -> PyResult<(PyObject, PyObject, PyObject, PyObject)> {
                Ok((
                    pyo3_asyncio::tokio::get_current_loop(py)?.into(),
                    py.import("asyncio")?.getattr("run_coroutine_threadsafe")?.into(),
                    handler.getattr(py, "handle_connection")?,
                    handler.getattr(py, "receive_datagram")?,
                ))
            })?;

        let python_callback_task = tokio::spawn(async move {
            while let Some(event) = smol_to_py_rx.recv().await {
                match event {
                    TransportEvent::ConnectionEstablished {
                        connection_id,
                        src_addr,
                        dst_addr,
                    } => {
                        let stream = TcpStream {
                            connection_id,
                            sockname,
                            peername: src_addr,
                            original_dst: dst_addr,
                            event_tx: event_tx.clone(),
                        };
                        Python::with_gil(|py| {
                            let stream = stream.into_py(py);
                            let coro = match handle_connection.call1(py, (stream.clone_ref(py), stream)) {
                                Ok(coro) => coro,
                                Err(err) => {
                                    err.print(py);
                                    return;
                                },
                            };
                            if let Err(err) = run_coroutine_threadsafe.call1(py, (coro, py_loop.as_ref(py))) {
                                err.print(py);
                            }
                        });
                    },
                    TransportEvent::DatagramReceived {
                        data,
                        src_addr,
                        dst_addr,
                    } => {
                        Python::with_gil(|py| {
                            let bytes: Py<PyBytes> = PyBytes::new(py, &data).into_py(py);
                            if let Err(err) = py_loop.call_method1(
                                py,
                                "call_soon_threadsafe",
                                (
                                    receive_datagram.as_ref(py),
                                    bytes,
                                    socketaddr_to_py(py, src_addr),
                                    socketaddr_to_py(py, dst_addr),
                                ),
                            ) {
                                err.print(py);
                            }
                        });
                    },
                }
            }
        });

        Ok(WireguardServer {
            python_callback_task,
            event_tx: py_to_smol_tx,
        })
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
fn start_server(py: Python<'_>, _host: String, _port: u16, handler: PyObject) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let server = WireguardServer::new(handler).await?;
        Ok(server)
    })
}

#[pymodule]
fn mitmproxy_wireguard(_py: Python, m: &PyModule) -> PyResult<()> {
    env_logger::builder().filter_level(log::LevelFilter::Debug).init();
    console_subscriber::init();

    m.add_function(wrap_pyfunction!(start_server, m)?)?;
    m.add_class::<WireguardServer>()?;
    m.add_class::<TcpStream>()?;
    m.add_class::<DatagramReceived>()?;
    Ok(())
}
