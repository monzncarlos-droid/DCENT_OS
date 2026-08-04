//! Execute pure [`dcentrald_common::TransportOp`] on live [`Bm1397PlusChainBackend`].
//!
//! # Why
//!
//! Decade P1-3 closed a HAL-free op language in `dcentrald-common::chain_transport`.
//! This module is the **first live adapter**: map admitted ops onto the existing
//! BM1397+ backend surface (serial / FPGA FIFO) without inventing a second API.
//!
//! # Status
//!
//! **EXPERIMENTAL** wire (host-proven via mock backend; production Serial/FPGA
//! backends already implement the trait). Callers must still admit ops via
//! pure policy before execute when protocol identity is known.
//!
//! Delay ops sleep the calling thread (bring-up is not the hot work path).

use dcentrald_common::{TransportOp, TransportOpError};

use crate::chain_backend::Bm1397PlusChainBackend;
use crate::{HalError, Result};

/// Map a HAL failure into the pure transport error vocabulary where possible.
#[derive(Debug)]
pub enum TransportExecuteError {
    /// Pure-policy refuse (empty frame, etc.) before I/O.
    Policy(TransportOpError),
    /// Backend I/O failure.
    Io(HalError),
}

impl std::fmt::Display for TransportExecuteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(e) => write!(f, "transport execute policy: {e}"),
            Self::Io(e) => write!(f, "transport execute I/O: {e}"),
        }
    }
}

impl std::error::Error for TransportExecuteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(e) => Some(e),
            Self::Io(e) => Some(e),
        }
    }
}

impl From<HalError> for TransportExecuteError {
    fn from(value: HalError) -> Self {
        Self::Io(value)
    }
}

impl From<TransportOpError> for TransportExecuteError {
    fn from(value: TransportOpError) -> Self {
        Self::Policy(value)
    }
}

/// Execute one pure transport op on a BM1397+ backend.
///
/// Does **not** re-run protocol×transport admission — callers that know the
/// silicon identity should call `dcentrald_common::admit_transport_op` first.
/// Empty work frames are still refused here as a last line of defense.
pub fn execute_transport_op_bm1397plus(
    backend: &dyn Bm1397PlusChainBackend,
    op: &TransportOp,
) -> std::result::Result<(), TransportExecuteError> {
    match op {
        TransportOp::SetBaudRate { baud } => {
            backend.set_baud_rate(*baud)?;
        }
        TransportOp::SetResponseBodyLen { body_len } => {
            backend.set_response_body_len(*body_len)?;
        }
        TransportOp::SendGetAddressBm1397Plus => {
            backend.send_get_address_bm1397plus()?;
        }
        TransportOp::SendChainInactiveBm1397Plus => {
            backend.send_chain_inactive_bm1397plus()?;
        }
        TransportOp::SendSetAddressBm1397Plus { addr } => {
            backend.send_set_address_bm1397plus(*addr)?;
        }
        TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value } => {
            backend.send_write_reg_broadcast_bm1397plus(*reg, *value)?;
        }
        TransportOp::SendWriteRegBm1397Plus {
            chip_addr,
            reg,
            value,
        } => {
            backend.send_write_reg_bm1397plus(*chip_addr, *reg, *value)?;
        }
        TransportOp::SendReadRegBm1397Plus { chip_addr, reg } => {
            backend.send_read_reg_bm1397plus(*chip_addr, *reg)?;
        }
        TransportOp::SendWorkFrame { frame } => {
            if frame.is_empty() {
                return Err(TransportOpError::EmptyWorkFrame.into());
            }
            backend.send_work_frame(frame)?;
        }
        TransportOp::DelayMs { ms } => {
            if *ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(u64::from(*ms)));
            }
        }
    }
    Ok(())
}

/// Execute an ordered pure op list; stop on first failure.
pub fn execute_transport_ops_bm1397plus(
    backend: &dyn Bm1397PlusChainBackend,
    ops: &[TransportOp],
) -> std::result::Result<(), TransportExecuteError> {
    for op in ops {
        execute_transport_op_bm1397plus(backend, op)?;
    }
    Ok(())
}

/// Host-test mock of [`Bm1397PlusChainBackend`] — records method calls, no hardware.
#[derive(Debug, Default, Clone)]
pub struct RecordingBm1397PlusBackend {
    pub chain_id: u8,
    pub label: &'static str,
    pub calls: Vec<String>,
    /// When set, the next call with this name returns Err.
    pub fail_on: Option<&'static str>,
}

impl RecordingBm1397PlusBackend {
    pub fn new(chain_id: u8, label: &'static str) -> Self {
        Self {
            chain_id,
            label,
            calls: Vec::new(),
            fail_on: None,
        }
    }

    fn push(&mut self, name: &'static str, detail: String) -> Result<()> {
        if self.fail_on == Some(name) {
            return Err(HalError::NotImplemented(
                "RecordingBm1397PlusBackend forced fail",
            ));
        }
        self.calls.push(format!("{name}:{detail}"));
        Ok(())
    }
}

// Recording backend needs interior mutability for &self trait methods.
use std::sync::Mutex;

/// Thread-safe recording backend for unit tests (`&self` trait surface).
#[derive(Debug)]
pub struct RecordingBm1397PlusBackendShared {
    inner: Mutex<RecordingBm1397PlusBackend>,
}

impl RecordingBm1397PlusBackendShared {
    pub fn new(chain_id: u8, label: &'static str) -> Self {
        Self {
            inner: Mutex::new(RecordingBm1397PlusBackend::new(chain_id, label)),
        }
    }

    pub fn calls(&self) -> Vec<String> {
        self.inner.lock().expect("lock").calls.clone()
    }

    pub fn set_fail_on(&self, name: Option<&'static str>) {
        self.inner.lock().expect("lock").fail_on = name;
    }
}

impl Bm1397PlusChainBackend for RecordingBm1397PlusBackendShared {
    fn set_baud_rate(&self, baud: u32) -> Result<()> {
        self.inner
            .lock()
            .expect("lock")
            .push("set_baud_rate", baud.to_string())
    }

    fn set_response_body_len(&self, body_len: usize) -> Result<()> {
        self.inner
            .lock()
            .expect("lock")
            .push("set_response_body_len", body_len.to_string())
    }

    fn send_get_address_bm1397plus(&self) -> Result<()> {
        self.inner
            .lock()
            .expect("lock")
            .push("send_get_address_bm1397plus", String::new())
    }

    fn send_chain_inactive_bm1397plus(&self) -> Result<()> {
        self.inner
            .lock()
            .expect("lock")
            .push("send_chain_inactive_bm1397plus", String::new())
    }

    fn send_set_address_bm1397plus(&self, addr: u8) -> Result<()> {
        self.inner
            .lock()
            .expect("lock")
            .push("send_set_address_bm1397plus", format!("0x{addr:02X}"))
    }

    fn send_write_reg_broadcast_bm1397plus(&self, reg: u8, value: u32) -> Result<()> {
        self.inner.lock().expect("lock").push(
            "send_write_reg_broadcast_bm1397plus",
            format!("reg=0x{reg:02X},value=0x{value:08X}"),
        )
    }

    fn send_write_reg_bm1397plus(&self, chip_addr: u8, reg: u8, value: u32) -> Result<()> {
        self.inner.lock().expect("lock").push(
            "send_write_reg_bm1397plus",
            format!("chip=0x{chip_addr:02X},reg=0x{reg:02X},value=0x{value:08X}"),
        )
    }

    fn send_read_reg_bm1397plus(&self, chip_addr: u8, reg: u8) -> Result<()> {
        self.inner.lock().expect("lock").push(
            "send_read_reg_bm1397plus",
            format!("chip=0x{chip_addr:02X},reg=0x{reg:02X}"),
        )
    }

    fn read_response_frame(&self, _out: &mut [u8], timeout_ms: u64) -> Result<usize> {
        self.inner
            .lock()
            .expect("lock")
            .push("read_response_frame", timeout_ms.to_string())?;
        Ok(0)
    }

    fn read_all_responses(&self, max_wait_ms: u64) -> Result<Vec<Vec<u8>>> {
        self.inner
            .lock()
            .expect("lock")
            .push("read_all_responses", max_wait_ms.to_string())?;
        Ok(Vec::new())
    }

    fn send_work_frame(&self, frame: &[u8]) -> Result<()> {
        self.inner
            .lock()
            .expect("lock")
            .push("send_work_frame", format!("len={}", frame.len()))
    }

    fn poll_nonce_frame(&self, _out: &mut [u8], timeout_ms: u64) -> Result<usize> {
        self.inner
            .lock()
            .expect("lock")
            .push("poll_nonce_frame", timeout_ms.to_string())?;
        Ok(0)
    }

    fn chain_id(&self) -> u8 {
        self.inner.lock().expect("lock").chain_id
    }

    fn transport_label(&self) -> &'static str {
        self.inner.lock().expect("lock").label
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcentrald_common::{
        admit_protocol_over_transport, admit_transport_op, plan_admitted_transport_ops,
        plan_pure_init_program, AsicProtocolIdentity, ChainTransportKind, TransportOp,
    };

    #[test]
    fn executes_get_address_and_set_address_on_mock() {
        let backend = RecordingBm1397PlusBackendShared::new(0, "mock-serial");
        execute_transport_op_bm1397plus(&backend, &TransportOp::SendGetAddressBm1397Plus)
            .expect("get address");
        execute_transport_op_bm1397plus(
            &backend,
            &TransportOp::SendSetAddressBm1397Plus { addr: 0x08 },
        )
        .expect("set address");
        let calls = backend.calls();
        assert_eq!(
            calls,
            vec![
                "send_get_address_bm1397plus:".to_string(),
                "send_set_address_bm1397plus:0x08".to_string(),
            ]
        );
    }

    #[test]
    fn executes_admitted_init_plan_for_bm1362_serial() {
        let admission =
            admit_protocol_over_transport(AsicProtocolIdentity::Bm1362, ChainTransportKind::Serial)
                .unwrap();
        let program = plan_pure_init_program(admission, 2, 0);
        let (_a, ops) = plan_admitted_transport_ops(
            AsicProtocolIdentity::Bm1362,
            ChainTransportKind::Serial,
            &program,
        )
        .unwrap();
        for op in &ops {
            admit_transport_op(admission, op).expect("pure admit");
        }
        let backend = RecordingBm1397PlusBackendShared::new(1, "mock");
        execute_transport_ops_bm1397plus(&backend, &ops).expect("execute plan");
        let calls = backend.calls();
        assert!(
            calls
                .iter()
                .any(|c| c.starts_with("send_get_address_bm1397plus")),
            "expected get-address in {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|c| c.starts_with("send_chain_inactive_bm1397plus")),
            "expected chain-inactive in {calls:?}"
        );
        assert!(
            calls
                .iter()
                .filter(|c| c.starts_with("send_set_address"))
                .count()
                >= 2,
            "expected two set-address calls in {calls:?}"
        );
    }

    #[test]
    fn empty_work_frame_refused_before_backend() {
        let backend = RecordingBm1397PlusBackendShared::new(0, "mock");
        let err = execute_transport_op_bm1397plus(
            &backend,
            &TransportOp::SendWorkFrame { frame: vec![] },
        )
        .unwrap_err();
        assert!(matches!(err, TransportExecuteError::Policy(_)));
        assert!(backend.calls().is_empty());
    }

    #[test]
    fn non_empty_work_frame_hits_backend() {
        let backend = RecordingBm1397PlusBackendShared::new(0, "mock");
        execute_transport_op_bm1397plus(
            &backend,
            &TransportOp::SendWorkFrame {
                frame: vec![0x55, 0xAA, 0x00],
            },
        )
        .expect("work");
        assert_eq!(backend.calls(), vec!["send_work_frame:len=3".to_string()]);
    }

    #[test]
    fn delay_ms_zero_is_no_op_without_backend_call() {
        let backend = RecordingBm1397PlusBackendShared::new(0, "mock");
        execute_transport_op_bm1397plus(&backend, &TransportOp::DelayMs { ms: 0 }).unwrap();
        assert!(backend.calls().is_empty());
    }

    #[test]
    fn baud_and_write_reg_map_to_backend_methods() {
        let backend = RecordingBm1397PlusBackendShared::new(0, "mock");
        execute_transport_ops_bm1397plus(
            &backend,
            &[
                TransportOp::SetBaudRate { baud: 115_200 },
                TransportOp::SetResponseBodyLen { body_len: 7 },
                TransportOp::SendWriteRegBroadcastBm1397Plus {
                    reg: 0x70,
                    value: 0x0A00_0000,
                },
                TransportOp::SendWriteRegBm1397Plus {
                    chip_addr: 0x04,
                    reg: 0x08,
                    value: 1,
                },
                TransportOp::SendReadRegBm1397Plus {
                    chip_addr: 0x04,
                    reg: 0x08,
                },
            ],
        )
        .unwrap();
        let calls = backend.calls();
        assert_eq!(calls.len(), 5);
        assert!(calls[0].contains("115200"));
        assert!(calls[1].contains("7"));
        assert!(calls[2].contains("0x70"));
        assert!(calls[3].contains("chip=0x04"));
        assert!(calls[4].starts_with("send_read_reg"));
    }

    #[test]
    fn backend_io_failure_surfaces_as_io_error() {
        let backend = RecordingBm1397PlusBackendShared::new(0, "mock");
        backend.set_fail_on(Some("send_get_address_bm1397plus"));
        let err = execute_transport_op_bm1397plus(&backend, &TransportOp::SendGetAddressBm1397Plus)
            .unwrap_err();
        assert!(matches!(err, TransportExecuteError::Io(_)));
    }
}
