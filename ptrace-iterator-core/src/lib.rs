//! The core functionality and types required by `tracer`.

use std::{
    convert::Infallible,
    ffi::{c_char, c_int, c_short, c_uchar, c_uint, c_ulong, c_ushort},
    fmt::{Debug, Display},
    io::IoSliceMut,
    os::fd::{AsRawFd, RawFd},
};

pub use nix;
use nix::{
    libc::{AT_FDCWD, c_long},
    sys::uio::{RemoteIoVec, process_vm_readv},
    unistd::Pid,
};
pub use syscalls;
use syscalls::Sysno;
use thiserror::Error;

pub mod io;

pub type Result<T> = core::result::Result<T, Error>;

/// Reads memory from the given user process.
///
/// # Safety
///
/// This function can only be called safely while the traced process is stopped on syscall entry.
/// After the syscall is invoked, all bets are off, since the kernel may change user memory as part
/// of the syscall handling, and all bets are even more off once control has returned to the
/// process.
pub unsafe fn read(pid: Pid, addr: Opaque, count: usize) -> Result<Box<[u8]>> {
    let mut buf = unsafe { Box::<[u8]>::new_uninit_slice(count).assume_init() };

    // Using process_vm_readv() has two advantages over the more traditional ptrace(PTRACE_PEEKDATA,
    // ...):
    //
    // 1. We can read more than a word at a time, which may be significantly more effective.
    // 2. We aren't subject to the same restrictions as ptrace() around the process being stopped.
    //    Of course, in practice reading without it being stopped would be unwise, but ptrace() is a
    //    little racy in practice, and sometimes you end up getting an ESRCH even when it should be
    //    stopped.
    process_vm_readv(
        pid,
        &mut [IoSliceMut::new(&mut buf)],
        &[RemoteIoVec {
            base: addr.0,
            len: count,
        }],
    )
    .map_err(|e| Error::Read { e, addr, pid })?;

    Ok(buf)
}

/// Reads memory from the given user process until a NUL byte is encountered.
///
/// Practically, this is useful to retrieve C strings from syscall parameters.
///
/// Note that this function is not particularly fast, since it has to read one word at a time.
///
/// # Safety
///
/// This function can only be called safely while the traced process is stopped on syscall entry.
/// After the syscall is invoked, all bets are off, since the kernel may change user memory as part
/// of the syscall handling, and all bets are even more off once control has returned to the
/// process.
pub unsafe fn read_to_nul(pid: Pid, mut addr: Opaque) -> Result<Vec<u8>> {
    // We have to read in a loop until we see a nul. We'll read a word at a time, which _should_
    // prevent us from going outside of the process mapping.
    let mut buf = Vec::new();
    const WORD_SIZE: usize = size_of::<c_long>();

    loop {
        let mut word = [0; WORD_SIZE];
        process_vm_readv(
            pid,
            &mut [IoSliceMut::new(&mut word)],
            &[RemoteIoVec {
                base: addr.0,
                len: WORD_SIZE,
            }],
        )
        .map_err(|e| Error::Read { e, addr, pid })?;

        if let Some(offset) = word.iter().position(|c| c == &b'\0') {
            buf.extend_from_slice(&word[0..offset]);
            return Ok(buf);
        }

        buf.extend_from_slice(&word);
        addr = addr.with_offset(WORD_SIZE);
    }
}

/// Reads memory from the given user process, and interprets it as the given type.
///
/// # Safety
///
/// This function can only be called safely while the traced process is stopped on syscall entry.
/// After the syscall is invoked, all bets are off, since the kernel may change user memory as part
/// of the syscall handling, and all bets are even more off once control has returned to the
/// process.
pub unsafe fn read_to_type<T: Sized>(pid: Pid, addr: Opaque) -> Result<T> {
    unsafe {
        let buf = read(pid, addr, size_of::<T>())?;
        Ok(std::ptr::read(Box::into_raw(buf) as *const T))
    }
}

#[derive(Debug, Error)]
pub enum Error {
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

    #[error("reading memory from PID {pid} at {addr:?}: {e}")]
    Read {
        #[source]
        e: nix::Error,
        addr: Opaque,
        pid: Pid,
    },

    #[error("parsing sockaddr from PID {pid} at {addr:?}")]
    SockaddrParse { addr: Opaque, pid: Pid },

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

/// A generic representation of a syscall.
#[derive(Debug, Clone)]
pub struct Other {
    pub nr: Sysno,
    pub args: [u64; 6],
}

pub trait TryFromArg: Copy + Sized {
    type Error: std::error::Error;

    fn try_from_arg(arg: u64) -> core::result::Result<Self, Self::Error>;
}

macro_rules! try_from_arg_as {
    ($ty:ty) => {
        impl TryFromArg for $ty {
            type Error = ::std::convert::Infallible;

            fn try_from_arg(arg: u64) -> ::core::result::Result<Self, Self::Error> {
                Ok(arg as $ty)
            }
        }
    };
}

try_from_arg_as!(c_char);
try_from_arg_as!(c_uchar);
try_from_arg_as!(c_short);
try_from_arg_as!(c_ushort);
try_from_arg_as!(c_int);
try_from_arg_as!(c_uint);
try_from_arg_as!(c_long);
try_from_arg_as!(c_ulong);
try_from_arg_as!(usize);
try_from_arg_as!(isize);

/// A file descriptor.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Fd(pub c_long);

impl Fd {
    /// Checks if the file descriptor represents the `AT_FDCWD` constant.
    pub fn is_at_working_directory(&self) -> bool {
        self.0 == (AT_FDCWD as c_long)
    }
}

impl Display for Fd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFromArg for Fd {
    type Error = Infallible;

    fn try_from_arg(arg: u64) -> core::result::Result<Self, Self::Error> {
        Ok(Self(c_long::try_from_arg(arg)?))
    }
}

impl From<c_long> for Fd {
    fn from(fd: c_long) -> Self {
        Self(fd)
    }
}

impl From<Fd> for c_long {
    fn from(fd: Fd) -> Self {
        fd.0
    }
}

impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.0 as RawFd
    }
}

impl TryFromArg for Pid {
    type Error = Infallible;

    fn try_from_arg(arg: u64) -> core::result::Result<Self, Self::Error> {
        Ok(Self::from_raw(arg as i32))
    }
}

/// An opaque pointer back into user data.
///
/// This doesn't really behave any differently to a usize, but helps disambiguate the cases.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Opaque(pub usize);

impl Opaque {
    pub fn at(&self, index: usize, type_size: usize) -> Self {
        self.with_offset(index * type_size)
    }

    pub fn is_null(&self) -> bool {
        // FIXME: this _could_ potentially be wrong on some weird architecture somewhere.
        self.0 == 0
    }

    pub fn with_offset(&self, offset: usize) -> Self {
        Self(self.0 + offset)
    }
}

impl Debug for Opaque {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

impl TryFromArg for Opaque {
    type Error = Infallible;

    fn try_from_arg(arg: u64) -> core::result::Result<Self, Self::Error> {
        Ok(Self(usize::try_from_arg(arg)?))
    }
}

impl<T> From<*const T> for Opaque {
    fn from(value: *const T) -> Self {
        Self(value.addr())
    }
}

impl<T> From<*mut T> for Opaque {
    fn from(value: *mut T) -> Self {
        Self(value.addr())
    }
}
