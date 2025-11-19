use std::process::Child;

use crate::nix::{libc::c_long, unistd::Pid};

/// A trait to convert anything that looks like a PID into a [`Pid`].
pub trait Piddable {
    /// Converts the value into a [`Pid`].
    fn into_pid(self) -> Pid;
}

impl Piddable for i32 {
    fn into_pid(self) -> Pid {
        Pid::from_raw(self)
    }
}

impl Piddable for u32 {
    fn into_pid(self) -> Pid {
        (self as i32).into_pid()
    }
}

impl Piddable for c_long {
    fn into_pid(self) -> Pid {
        (self as i32).into_pid()
    }
}

impl Piddable for Pid {
    fn into_pid(self) -> Pid {
        self
    }
}

impl Piddable for &Child {
    fn into_pid(self) -> Pid {
        self.id().into_pid()
    }
}

impl<T: Copy + Piddable> Piddable for &T {
    fn into_pid(self) -> Pid {
        (*self).into_pid()
    }
}
