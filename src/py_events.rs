use std::fmt::{Display, Formatter};
use std::net::SocketAddr;

use pyo3::prelude::*;
use pyo3::{IntoPy, PyObject, Python};

#[derive(Clone, Debug)]
pub struct PySockAddr(pub SocketAddr);

impl Display for PySockAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<SocketAddr> for PySockAddr {
    fn from(addr: SocketAddr) -> Self {
        Self(addr)
    }
}

impl IntoPy<PyObject> for PySockAddr {
    fn into_py(self, py: Python<'_>) -> PyObject {
        match self.0 {
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
}


#[pyclass]
#[derive(Debug)]
pub struct DatagramReceived {
    #[pyo3(get)]
    pub src_addr: PySockAddr,
    #[pyo3(get)]
    pub dst_addr: PySockAddr,
    #[pyo3(get)]
    pub data: Vec<u8>,
}

#[pymethods]
impl DatagramReceived {
    fn __repr__(&self) -> String {
        format!(
            "DatagramReceived({}, {}, {:x?})",
            self.src_addr, self.dst_addr, self.data
        )
    }
}
