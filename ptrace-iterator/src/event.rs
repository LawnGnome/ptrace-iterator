//! Types related to ptrace events.

use std::fmt::Debug;

use crate::{
    Syscall, Sysno,
    nix::{
        sys::{
            ptrace,
            signal::Signal::{self as RawSignal, SIGTRAP},
            wait::WaitStatus,
        },
        unistd::Pid,
    },
    pending::{Pending, PendingSyscalls},
};

/// A ptrace event from a traced process.
///
/// Process execution restarts once the [`Event`] is dropped. Critically, this means that any data
/// contained within, or pointed to by, the event **must** be cloned out of the event and/or the
/// tracee's memory space before the event is dropped.
///
/// Most of the terms here come from the C `ptrace` API; referencing questions against [the
/// `ptrace(2)` man page](https://man7.org/linux/man-pages/man2/ptrace.2.html) is strongly
/// recommended as a result.
pub enum Event<UserData> {
    Clone(Clone),
    Exited(Exited),
    Signal(Signal),
    Stopped(Stopped),
    SyscallEntry(SyscallEntry<UserData>),
    SyscallExit(SyscallExit<UserData>),
    SyscallNone(SyscallNone),
    SyscallSeccomp(SyscallSeccomp),
    Other(WaitStatus),
}

impl<UserData> Event<UserData> {
    fn restart_pid(&self) -> Option<Pid> {
        match self {
            Event::Clone(Clone { pid, .. }) => Some(*pid),
            Event::Exited(..) => None,
            Event::Signal(Signal { pid, .. }) => Some(*pid),
            Event::Stopped(Stopped { pid, .. }) => Some(*pid),
            Event::SyscallEntry(SyscallEntry { pid, .. }) => Some(*pid),
            Event::SyscallExit(SyscallExit { pid, .. }) => Some(*pid),
            Event::SyscallNone(SyscallNone { pid, .. }) => Some(*pid),
            Event::SyscallSeccomp(SyscallSeccomp { pid, .. }) => Some(*pid),
            Event::Other(..) => None,
        }
    }
}

impl<UserData> Debug for Event<UserData> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clone(arg0) => f.debug_tuple("Clone").field(arg0).finish(),
            Self::Exited(arg0) => f.debug_tuple("Exited").field(arg0).finish(),
            Self::Signal(arg0) => f.debug_tuple("Signal").field(arg0).finish(),
            Self::Stopped(arg0) => f.debug_tuple("Stopped").field(arg0).finish(),
            Self::SyscallEntry(arg0) => f.debug_tuple("SyscallEntry").field(arg0).finish(),
            Self::SyscallExit(arg0) => f.debug_tuple("SyscallExit").field(arg0).finish(),
            Self::SyscallNone(arg0) => f.debug_tuple("SyscallNone").field(arg0).finish(),
            Self::SyscallSeccomp(arg0) => f.debug_tuple("SyscallSeccomp").field(arg0).finish(),
            Self::Other(arg0) => f.debug_tuple("Other").field(arg0).finish(),
        }
    }
}

impl<UserData> Drop for Event<UserData> {
    fn drop(&mut self) {
        let sig = match self {
            Event::Signal(Signal { signal, .. }) if *signal != SIGTRAP => Some(*signal),
            Event::Stopped(Stopped { signal, .. }) if *signal != SIGTRAP => Some(*signal),
            _ => None,
        };

        if let Some(pid) = self.restart_pid()
            && let Err(e) = ptrace::syscall(pid, sig)
        {
            // We don't expect to be able to restart if this was an exit syscall, so only warn if
            // it wasn't.
            if let Event::SyscallEntry(entry) = self
                && entry.syscall().nr() == Sysno::exit
            {
                return;
            }

            #[cfg(feature = "tracing")]
            tracing::error!(%e, %pid, event = ?self, "error restarting PID in response to event");

            #[cfg(not(feature = "tracing"))]
            eprintln!("error restarting PID {pid} in response to {self:?}: {e}");
        }
    }
}

/// Event generated when a process is cloned.
#[derive(Debug, Clone, Copy)]
pub struct Clone {
    pub(crate) child_pid: Pid,
    pub(crate) pid: Pid,
    pub(crate) signal: RawSignal,
    pub(crate) event: i32,
}

impl Clone {
    /// Returns the PID of the new child process.
    pub fn child_pid(&self) -> Pid {
        self.child_pid
    }

    /// Returns the PID of the parent process that was just cloned.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Returns the raw signal from the ptrace event.
    ///
    /// In practice, this is always [`SIGTRAP`].
    pub fn signal(&self) -> RawSignal {
        self.signal
    }

    /// Returns the raw event code from the ptrace event.
    ///
    /// In practice, this is always [`nix::libc::PTRACE_EVENT_CLONE`].
    pub fn event(&self) -> i32 {
        self.event
    }
}

/// Event generated when a process exits.
#[derive(Debug, Clone, Copy)]
pub struct Exited {
    pub(crate) pid: Pid,
    pub(crate) status: i32,
}

impl Exited {
    /// Returns the PID of the process that exited.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Returns the exit status of the process that exited.
    pub fn status(&self) -> i32 {
        self.status
    }
}

/// Event generated when a process receives a signal.
#[derive(Debug, Clone, Copy)]
pub struct Signal {
    pub(crate) pid: Pid,
    pub(crate) signal: RawSignal,
    pub(crate) dumped: bool,
}

impl Signal {
    /// Returns the PID of the process that received the signal.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Returns the signal that the process received.
    pub fn signal(&self) -> RawSignal {
        self.signal
    }

    /// Returns true if the process generated a core dump.
    pub fn dumped(&self) -> bool {
        self.dumped
    }
}

/// Event generated when a process stops without signal tracing enabled.
///
/// This crate never calls [`nix::libc::waitid`] or [`nix::libc::waitpid`] with the
/// [`nix::libc::WUNTRACED`] option set, so this event should never be generated in normal use.
#[derive(Debug)]
pub struct Stopped {
    pub(crate) pid: Pid,
    pub(crate) signal: RawSignal,
}

impl Stopped {
    /// Returns the PID of the process that stopped.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Returns the signal that stopped the process.
    pub fn signal(&self) -> RawSignal {
        self.signal
    }
}

/// Event generated when a syscall is called.
///
/// Arguments to the syscall can be accessed — with care, and usually some `unsafe` — via
/// [`SyscallEntry::syscall`]. Similarly, [`SyscallEntry::info`] is likely to be useful to unwind
/// the process stack.
///
/// Userdata can be set on the syscall using [`SyscallEntry::set_userdata`]. If set, it can then be
/// accessed again on syscall exit using [`SyscallExit::userdata`].
pub struct SyscallEntry<UserData> {
    pub(crate) pid: Pid,
    pub(crate) info: SyscallInfo,
    pub(crate) syscall: Option<Syscall>,
    pub(crate) userdata: Option<UserData>,
    pub(crate) pending: PendingSyscalls<UserData>,
}

impl<UserData> SyscallEntry<UserData> {
    /// Returns the PID of the process that invoked the syscall.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Returns information about the process, most notably the instruction and stack pointers.
    pub fn info(&self) -> &'_ SyscallInfo {
        &self.info
    }

    /// Returns the syscall itself.
    ///
    /// If using the syscall to access syscall arguments, care should be taken to ensure that they
    /// are safe to read before the syscall.
    pub fn syscall(&self) -> &'_ Syscall {
        #[expect(clippy::unwrap_used)]
        // unwrap() here because this is always set until Drop, after which this shouldn't be
        // accessible anyway.
        self.syscall.as_ref().unwrap()
    }

    /// Removes any userdata that has been set on the syscall.
    pub fn remove_userdata(&mut self) {
        self.userdata = None;
    }

    /// Sets userdata on the syscall.
    pub fn set_userdata(&mut self, userdata: UserData) {
        self.userdata = Some(userdata);
    }

    /// Accesses any userdata that has been set on the syscall.
    pub fn userdata(&self) -> Option<&'_ UserData> {
        self.userdata.as_ref()
    }

    /// Mutably accesses any userdata that has been set on the syscall.
    pub fn userdata_mut(&mut self) -> Option<&'_ mut UserData> {
        self.userdata.as_mut()
    }
}

impl<UserData> Debug for SyscallEntry<UserData> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyscallEntry")
            .field("pid", &self.pid)
            .field("info", &self.info)
            .field("syscall", &self.syscall)
            .field("has userdata", &self.userdata.is_some())
            .finish()
    }
}

impl<UserData> Drop for SyscallEntry<UserData> {
    fn drop(&mut self) {
        // Set the pending syscall metadata in the tracer.
        #[expect(clippy::unwrap_used)]
        self.pending.upsert(
            self.pid,
            Pending {
                // unwrap() here because this is always set until Drop.
                syscall: self.syscall.take().unwrap(),
                userdata: self.userdata.take(),
            },
        );
    }
}

/// Event generated when a syscall returns.
pub struct SyscallExit<UserData> {
    pub(crate) pid: Pid,
    pub(crate) info: SyscallInfo,
    pub(crate) syscall: Option<Syscall>,
    pub(crate) sval: i64,
    pub(crate) is_error: bool,
    pub(crate) userdata: Option<UserData>,
}

impl<UserData> SyscallExit<UserData> {
    /// Returns the PID of the process that is about to get the result of the syscall.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Returns information about the process, most notably the instruction and stack pointers.
    pub fn info(&self) -> &'_ SyscallInfo {
        &self.info
    }

    /// Returns the syscall that completed.
    ///
    /// This may be `None` if the tracer wasn't configured when the syscall was made.
    ///
    /// If using the syscall to access syscall arguments, care should be taken to ensure that they
    /// are safe to read after the syscall.
    pub fn syscall(&self) -> Option<&'_ Syscall> {
        self.syscall.as_ref()
    }

    /// Returns the return value of the syscall.
    pub fn sval(&self) -> i64 {
        self.sval
    }

    /// Returns true if the syscall errored.
    pub fn is_error(&self) -> bool {
        self.is_error
    }

    /// Takes the userdata from the [`SyscallExit`], if userdata was set using
    /// [`SyscallEntry::set_userdata`].
    pub fn take_userdata(&mut self) -> Option<UserData> {
        self.userdata.take()
    }

    /// Accesses the userdata from the [`SyscallExit`], if userdata was set using
    /// [`SyscallEntry::set_userdata`].
    pub fn userdata(&self) -> Option<&'_ UserData> {
        self.userdata.as_ref()
    }
}

impl<UserData> Debug for SyscallExit<UserData> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyscallExit")
            .field("pid", &self.pid)
            .field("info", &self.info)
            .field("syscall", &self.syscall)
            .field("sval", &self.sval)
            .field("is_error", &self.is_error)
            .field("has userdata", &self.userdata.is_some())
            .finish()
    }
}

/// Event generated when a syscall was made, but [`nix::libc::PTRACE_O_TRACESYSGOOD`] was unset.
///
/// [`crate::Tracer`] sets this unconditionally, so in practice it is unlikely that this event will
/// ever be seen.
#[derive(Debug)]
pub struct SyscallNone {
    pub(crate) pid: Pid,
    pub(crate) info: SyscallInfo,
}

impl SyscallNone {
    /// Returns the PID of the process that made the syscall.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Returns information about the process, most notably the instruction and stack pointers.
    pub fn info(&self) -> &'_ SyscallInfo {
        &self.info
    }
}

/// Event generated when a syscall triggers a [`nix::libc::SECCOMP_RET_TRACE`] rule.
///
/// [`crate::Tracer`] currently lacks an option to set this flag, so in practice this event is
/// unlikely to be seen.
#[derive(Debug)]
pub struct SyscallSeccomp {
    pub(crate) pid: Pid,
    pub(crate) info: SyscallInfo,
    pub(crate) syscall: Syscall,
    pub(crate) ret_data: u32,
}

impl SyscallSeccomp {
    /// Returns the PID of the process that made the syscall.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Returns information about the process, most notably the instruction and stack pointers.
    pub fn info(&self) -> &'_ SyscallInfo {
        &self.info
    }

    /// Returns the syscall itself.
    ///
    /// If using the syscall to access syscall arguments, care should be taken to ensure that they
    /// are safe to read before the syscall.
    pub fn syscall(&self) -> &'_ Syscall {
        &self.syscall
    }

    /// Returns the [`nix::libc::SECCOMP_RET_DATA`] returned by the seccomp rule.
    pub fn ret_data(&self) -> u32 {
        self.ret_data
    }
}

/// Information about the process that made a syscall.
///
/// This is mostly useful to get the current call stack of the process using something like
/// `unwind`.
#[derive(Debug)]
pub struct SyscallInfo {
    /// The architecture as defined by seccomp's `AUDIT_ARCH_* constants`.
    pub arch: u32,

    /// The current instruction pointer of the process.
    pub instruction_pointer: u64,

    /// The current stack pointer of the process.
    pub stack_pointer: u64,
}
