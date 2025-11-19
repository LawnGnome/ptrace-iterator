use std::convert::Infallible;

use crate::nix::unistd::Pid;
use thiserror::Error;

/// Errors returned by `ptrace-iterator`.
#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] crate::core::Error),

    #[error("getting event details on PID {pid}: {e}")]
    GetEvent {
        #[source]
        e: nix::Error,
        pid: Pid,
    },

    #[error(transparent)]
    Infallible(#[from] Infallible),

    #[error("invalid syscall info op on PID {pid}: {op}")]
    InvalidOp { op: u8, pid: Pid },

    #[error("setting initial options on PID {pid}: {e}")]
    Options {
        #[source]
        e: nix::Error,
        pid: Pid,
    },

    #[error("reading memory from PID {pid} at {addr:016x}: {e}")]
    Read {
        #[source]
        e: nix::Error,
        addr: usize,
        pid: Pid,
    },

    #[error("tracing syscalls on PID {pid}: {e}")]
    Syscall {
        #[source]
        e: nix::Error,
        pid: Pid,
    },

    #[error("getting syscall info on PID {pid}: {e}")]
    SyscallInfo {
        #[source]
        e: nix::Error,
        pid: Pid,
    },

    #[error("waiting for PID {pid} (and its descendents): {e}")]
    Wait {
        #[source]
        e: nix::Error,
        pid: Pid,
    },
}
