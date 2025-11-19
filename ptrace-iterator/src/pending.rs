use std::{cell::RefCell, collections::HashMap, fmt::Debug, rc::Rc};

use nix::unistd::Pid;

use crate::Syscall;

/// Process-specific tracking for in-flight syscalls, including any user data.
pub struct PendingSyscalls<UserData> {
    // Note that we're using Rc and RefCell intentionally here: tracers cannot be Sync or Send due
    // to how ptrace works, so there's no need for the extra overhead of Arc and Mutex.
    inner: Rc<RefCell<HashMap<Pid, Pending<UserData>>>>,
}

impl<UserData> PendingSyscalls<UserData> {
    pub fn new() -> Self {
        Self {
            inner: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    pub fn remove(&self, pid: Pid) -> Option<Pending<UserData>> {
        self.inner.borrow_mut().remove(&pid)
    }

    pub fn upsert(&self, pid: Pid, pending: Pending<UserData>) {
        self.inner.borrow_mut().insert(pid, pending);
    }
}

impl<UserData> Clone for PendingSyscalls<UserData> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

pub struct Pending<UserData> {
    pub syscall: Syscall,
    pub userdata: Option<UserData>,
}

impl<UserData> Debug for Pending<UserData> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("syscall", &self.syscall)
            .field("has userdata", &self.userdata.is_some())
            .finish()
    }
}
