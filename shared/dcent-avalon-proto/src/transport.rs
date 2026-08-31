// SPDX-License-Identifier: GPL-3.0-or-later
//
// SysV msgq transport for mm_pkg. Linux/BSD only.
//
// Identical to the IPC mechanism used by Canaan's `cg_miner` (Linux little
// core) and `asic_miner_e` (RT-Smart big core) on K230 — see
//    §5.
//
// Both Avalon_Nano3s (home Nano 3S) and Avalon_mm (industrial A14xx/A15xx)
// converge on the same key derivation (`ftok("/dev/null", b'A')`) and the same
// 268-byte packet body. So this transport drops in identically for both
// DCENT_axe Avalon and DCENT_OS Avalon.
//
// mtype convention:
//   0x1 = host (us) → ASIC daemon
//   0x2 = ASIC daemon → host
//
// `msgsnd(2)` ABI requires a `c_long` mtype prefix; the caller supplies it via
// the dedicated send/recv methods rather than embedding mtype into MmPkg.

use crate::mm_pkg::{MmPkg, MmPkgError, MM_PKG_SIZE};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("ftok failed: {0}")]
    Ftok(std::io::Error),

    #[error("msgget failed: {0}")]
    MsgGet(std::io::Error),

    #[error("msgsnd failed: {0}")]
    MsgSnd(std::io::Error),

    #[error("msgrcv failed: {0}")]
    MsgRcv(std::io::Error),

    #[error("short msgrcv: got {got} bytes, expected {want}")]
    ShortRead { got: usize, want: usize },

    #[error("unexpected msgrcv mtype: {0} (expected 0x1 or 0x2)")]
    UnexpectedMtype(i64),

    #[error("packet codec: {0}")]
    Codec(#[from] MmPkgError),
}

/// Direction of an mm_pkg, encoded as the SysV msgq `mtype` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum Direction {
    /// Host (Linux little core) → ASIC daemon (RT-Smart big core).
    HostToAsic = 0x1,
    /// ASIC daemon → host.
    AsicToHost = 0x2,
}

#[cfg(unix)]
mod unix_impl {
    use super::*;
    use libc::{c_int, c_long, key_t};
    use std::ffi::CString;
    use std::io;
    use std::mem::MaybeUninit;

    /// Default key path used by Canaan firmware. Canaan derives the SysV msgq
    /// key from `/dev/null + 'A'`. Both home and industrial use this path.
    pub const DEFAULT_KEY_PATH: &str = "/dev/null";
    pub const DEFAULT_KEY_PROJ_ID: u8 = b'A';

    #[repr(C)]
    struct Msgbuf {
        mtype: c_long,
        mtext: [u8; MM_PKG_SIZE],
    }

    /// Linux SysV message queue holding mm_pkg payloads.
    pub struct SysVMsgQ {
        msqid: c_int,
    }

    impl SysVMsgQ {
        /// Open (or create) the message queue using the canonical key path.
        pub fn open_default() -> Result<Self, TransportError> {
            Self::open(DEFAULT_KEY_PATH, DEFAULT_KEY_PROJ_ID)
        }

        /// Open (or create) the message queue using a custom key.
        pub fn open(key_path: &str, proj_id: u8) -> Result<Self, TransportError> {
            let cpath = CString::new(key_path).map_err(|_| {
                TransportError::Ftok(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "key_path contains an interior NUL byte",
                ))
            })?;
            // SAFETY: cpath is a valid CString; ftok writes no memory.
            let key: key_t = unsafe { libc::ftok(cpath.as_ptr(), proj_id as c_int) };
            if key == -1 {
                return Err(TransportError::Ftok(io::Error::last_os_error()));
            }
            // SAFETY: msgget is thread-safe; flags `IPC_CREAT | 0o666` create
            // the queue if missing or open the existing one.
            let msqid = unsafe { libc::msgget(key, libc::IPC_CREAT | 0o666) };
            if msqid == -1 {
                return Err(TransportError::MsgGet(io::Error::last_os_error()));
            }
            Ok(Self { msqid })
        }

        /// Send an mm_pkg. The `direction` is encoded as msgq `mtype`.
        pub fn send(&self, direction: Direction, pkg: &MmPkg) -> Result<(), TransportError> {
            let buf = Msgbuf {
                mtype: direction as c_long,
                mtext: pkg.encode(),
            };
            // SAFETY: Msgbuf has the layout msgsnd(2) expects: leading c_long
            // mtype followed by mtext. Buffer size is MM_PKG_SIZE bytes.
            let rc = unsafe {
                libc::msgsnd(
                    self.msqid,
                    &buf as *const Msgbuf as *const libc::c_void,
                    MM_PKG_SIZE,
                    0,
                )
            };
            if rc == -1 {
                return Err(TransportError::MsgSnd(io::Error::last_os_error()));
            }
            Ok(())
        }

        /// Receive an mm_pkg matching the given direction.
        /// Pass `None` to receive any direction (mtype filter = 0).
        pub fn recv(&self, want: Option<Direction>) -> Result<MmPkg, TransportError> {
            let mut buf = MaybeUninit::<Msgbuf>::uninit();
            let mtype: c_long = match want {
                Some(d) => d as c_long,
                None => 0,
            };
            // SAFETY: msgrcv writes up to MM_PKG_SIZE bytes into buf.mtext and
            // sets mtype. We read both fields below only on success.
            let rc = unsafe {
                libc::msgrcv(
                    self.msqid,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    MM_PKG_SIZE,
                    mtype,
                    0,
                )
            };
            if rc == -1 {
                return Err(TransportError::MsgRcv(io::Error::last_os_error()));
            }
            // msgrcv copies exactly `rc` bytes into mtext. Without MSG_NOERROR an
            // over-long message is rejected with E2BIG (already handled by the
            // rc == -1 branch above), so the only remaining risk is a SHORT
            // message that leaves mtext[rc..] UNINITIALISED. Calling
            // assume_init() over the whole Msgbuf in that case — and then
            // decoding all MM_PKG_SIZE bytes — reads uninitialised memory
            // (undefined behaviour). Reject a short read fail-closed BEFORE
            // touching the buffer.
            let got = rc as usize;
            if got != MM_PKG_SIZE {
                return Err(TransportError::ShortRead {
                    got,
                    want: MM_PKG_SIZE,
                });
            }
            // SAFETY: msgrcv wrote exactly MM_PKG_SIZE bytes, so buf is fully
            // initialised.
            let buf = unsafe { buf.assume_init() };
            // The codec needs the direction to interpret the compound type
            // word, and `want == None` does not tell us which arrived. Derive
            // it from the mtype the kernel stamped on the message; fail closed
            // on any mtype this transport never sends.
            let codec_direction = match buf.mtype {
                x if x == Direction::HostToAsic as c_long => {
                    crate::mm_pkg::Direction::HostToMm
                }
                x if x == Direction::AsicToHost as c_long => {
                    crate::mm_pkg::Direction::MmToHost
                }
                other => return Err(TransportError::UnexpectedMtype(other as i64)),
            };
            Ok(MmPkg::decode(&buf.mtext, codec_direction)?)
        }

        /// Non-blocking receive: `Ok(None)` when no matching message is
        /// queued (EAGAIN/ENOMSG). Same decode contract as `recv`.
        pub fn try_recv(&self, want: Option<Direction>) -> Result<Option<MmPkg>, TransportError> {
            let mut buf = MaybeUninit::<Msgbuf>::uninit();
            let mtype: c_long = match want {
                Some(d) => d as c_long,
                None => 0,
            };
            // SAFETY: same contract as `recv`; IPC_NOWAIT makes the call
            // non-blocking and EAGAIN/ENOMSG surface as rc == -1.
            let rc = unsafe {
                libc::msgrcv(
                    self.msqid,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    MM_PKG_SIZE,
                    mtype,
                    libc::IPC_NOWAIT,
                )
            };
            if rc == -1 {
                let err = io::Error::last_os_error();
                return match err.raw_os_error() {
                    Some(libc::EAGAIN) | Some(libc::ENOMSG) => Ok(None),
                    _ => Err(TransportError::MsgRcv(err)),
                };
            }
            let got = rc as usize;
            if got != MM_PKG_SIZE {
                return Err(TransportError::ShortRead {
                    got,
                    want: MM_PKG_SIZE,
                });
            }
            // SAFETY: msgrcv wrote exactly MM_PKG_SIZE bytes.
            let buf = unsafe { buf.assume_init() };
            let codec_direction = match buf.mtype {
                x if x == Direction::HostToAsic as c_long => {
                    crate::mm_pkg::Direction::HostToMm
                }
                x if x == Direction::AsicToHost as c_long => {
                    crate::mm_pkg::Direction::MmToHost
                }
                other => return Err(TransportError::UnexpectedMtype(other as i64)),
            };
            Ok(Some(MmPkg::decode(&buf.mtext, codec_direction)?))
        }

        /// Underlying msqid for diagnostic purposes.
        pub fn msqid(&self) -> c_int {
            self.msqid
        }
    }
}

#[cfg(unix)]
pub use unix_impl::{SysVMsgQ, DEFAULT_KEY_PATH, DEFAULT_KEY_PROJ_ID};
