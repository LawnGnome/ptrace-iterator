use std::{os::unix::process::CommandExt, process::Command};

use crate::nix::sys::ptrace;

/// A trait providing a method to set up tracing for a [`Command`] that is being spawned.
pub trait CommandTrace {
    /// Indicates that the command expects to be traced by its parent.
    fn traceme(&mut self) -> &mut Self;
}

impl CommandTrace for Command {
    fn traceme(&mut self) -> &mut Self {
        unsafe {
            self.pre_exec(|| ptrace::traceme().map_err(std::io::Error::other));
        }
        self
    }
}
