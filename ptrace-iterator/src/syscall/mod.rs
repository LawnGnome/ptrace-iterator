//! Types for specific syscalls.

use std::{ffi::c_void, fmt::Debug, mem::MaybeUninit, rc::Rc};

use nix::{
    errno::Errno,
    libc::{
        PTRACE_GET_SYSCALL_INFO, PTRACE_SYSCALL_INFO_ENTRY, PTRACE_SYSCALL_INFO_EXIT,
        PTRACE_SYSCALL_INFO_NONE, PTRACE_SYSCALL_INFO_SECCOMP, ptrace_syscall_info,
    },
    unistd::Pid,
};
pub use syscalls::Sysno;

use crate::Error;
pub use raw::*;

mod raw;

/// Syscall information from a tracer [`Event`][super::Event].
///
/// Each syscall generates multiple events with different [`Op`]s, which can be accessed via the
/// [`op`][Info::op] field.
///
/// This is a thin wrapper around `ptrace_syscall_info`, which is documented as part of `ptrace`.
#[derive(Clone)]
pub struct Info {
    pub op: Op,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub stack_pointer: u64,

    // Make Info !Send + !Sync, since ptrace essentially is.
    _phantom: Rc<()>,
}

impl Info {
    pub(crate) fn from_pid(pid: Pid) -> Result<Self, Error> {
        let info = ptrace_syscall_info(pid)?;

        Ok(Self {
            op: match info.op {
                PTRACE_SYSCALL_INFO_NONE => Op::None,
                PTRACE_SYSCALL_INFO_ENTRY => {
                    let entry = unsafe { info.u.entry };
                    Op::Entry {
                        syscall: Syscall::try_from_raw(entry.nr as u32, entry.args)?,
                    }
                }
                PTRACE_SYSCALL_INFO_EXIT => Op::Exit {
                    sval: unsafe { info.u.exit }.sval,
                    is_error: unsafe { info.u.exit }.is_error != 0,
                },
                PTRACE_SYSCALL_INFO_SECCOMP => {
                    let seccomp = unsafe { info.u.seccomp };
                    Op::Seccomp {
                        syscall: Syscall::try_from_raw(seccomp.nr as u32, seccomp.args)?,
                        ret_data: seccomp.ret_data,
                    }
                }
                op => return Err(Error::InvalidOp { op, pid }),
            },
            arch: info.arch,
            instruction_pointer: info.instruction_pointer,
            stack_pointer: info.stack_pointer,
            _phantom: Rc::new(()),
        })
    }
}

impl Debug for Info {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyscallInfo")
            .field("op", &self.op)
            .field("arch", &self.arch)
            .field(
                "instruction_pointer",
                &format!("{:#016x}", self.instruction_pointer),
            )
            .field("stack_pointer", &format!("{:#016x}", self.stack_pointer))
            .finish()
    }
}

/// The type of syscall stop.
///
/// Note that arguments are only accessible in [`Op::Entry`], so any required arguments need to be
/// cloned out for future use at that point.
#[derive(Debug, Clone)]
pub enum Op {
    None,
    Entry { syscall: Syscall },
    Exit { sval: i64, is_error: bool },
    Seccomp { syscall: Syscall, ret_data: u32 },
}

fn ptrace_syscall_info(pid: Pid) -> Result<ptrace_syscall_info, Error> {
    // nix's safe ptrace wrapper provides a syscall_info function, but it seems to return junk a
    // lot of the time. Let's just call into libc ourselves.
    let mut info = MaybeUninit::<ptrace_syscall_info>::uninit();
    unsafe {
        if nix::libc::ptrace(
            PTRACE_GET_SYSCALL_INFO,
            pid,
            size_of::<ptrace_syscall_info>() as *mut c_void,
            info.as_mut_ptr(),
        ) == -1
        {
            Err(Error::SyscallInfo {
                e: Errno::last(),
                pid,
            })
        } else {
            Ok(info.assume_init())
        }
    }
}
