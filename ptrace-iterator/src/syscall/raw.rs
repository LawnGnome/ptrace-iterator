use std::{
    ffi::{OsString, c_char, c_int, c_long, c_uint, c_ulong, c_ushort, c_void},
    mem::offset_of,
    os::unix::ffi::OsStringExt,
    path::PathBuf,
};

use linux_aio_sys::{io_event, iocb};
use linux_raw_sys::{
    general::{
        __kernel_clockid_t, __kernel_daddr_t, __kernel_fd_set, __kernel_gid_t, __kernel_itimerspec,
        __kernel_key_t, __kernel_loff_t, __kernel_mode_t, __kernel_old_itimerval,
        __kernel_old_timeval, __kernel_rwf_t, __kernel_timer_t, __kernel_timespec, __kernel_uid_t,
        __kernel_uid32_t, cachestat, cachestat_range, cap_user_data_t, cap_user_header_t,
        clone_args, epoll_event, futex_waitv, iovec, kernel_sigset_t, linux_dirent64, mnt_id_req,
        mount_attr, open_how, pollfd, rlimit, rlimit64, robust_list_head, rusage, sigevent,
        siginfo, siginfo_t, sigset_t, stack_t, stat, statfs, statx, timeval, timezone,
    },
    io_uring::io_uring_params,
    landlock::{landlock_rule_type, landlock_ruleset_attr},
    net::{mmsghdr, sockaddr},
    system::{old_utsname, sysinfo},
};

use crate::{
    core::{self as core, Fd, Opaque, io::Msghdr},
    nix::{
        libc::{
            self, cpu_set_t, mq_attr, sched_attr, sched_param, sembuf, shmid_ds, socklen_t, timex,
            utimbuf,
        },
        sys::socket::{SockaddrLike, SockaddrStorage},
        unistd::Pid,
    },
    syscall,
};

/// An actual syscall and its arguments.
///
/// # Safety
///
/// All accessors are marked unsafe; knowing which arguments can be accessed safely at syscall
/// entry or exit is beyond the scope of this documentation, and many arguments require reads into
/// the tracee's memory, which is itself unsafe.
#[syscall(core = crate::core)]
pub enum Syscall {
    #[syscall(read)]
    Read {
        fd: Fd,
        #[syscall(ptr(count = count))]
        buf: u8,
        #[syscall(private)]
        count: usize,
    },

    #[syscall(write)]
    Write {
        fd: Fd,
        #[syscall(ptr(count = count))]
        buf: u8,
        #[syscall(private)]
        count: usize,
    },

    #[syscall(open)]
    Open {
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        flags: c_int,
        mode: c_ushort,
    },

    #[syscall(close)]
    Close { fd: Fd },

    #[syscall(stat)]
    Stat {
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        #[syscall(ptr())]
        statbuf: stat,
    },

    #[syscall(fstat)]
    Fstat {
        fd: Fd,
        #[syscall(ptr())]
        statbuf: stat,
    },

    #[syscall(lstat)]
    Lstat {
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        #[syscall(ptr())]
        statbuf: stat,
    },

    #[syscall(poll)]
    Poll {
        #[syscall(ptr(count=nfds))]
        ufds: pollfd,
        #[syscall(private)]
        nfds: c_uint,
        timeout: c_int,
    },

    #[syscall(lseek)]
    Lseek {
        fd: Fd,
        offset: isize,
        whence: c_uint,
    },

    #[syscall(mmap)]
    Mmap {
        #[syscall(ptr(opaque))]
        addr: Opaque,
        len: usize,
        prot: c_ulong,
        flags: c_ulong,
        fd: c_ulong,
        off: c_ulong,
    },

    #[syscall(mprotect)]
    Mprotect {
        #[syscall(ptr(opaque))]
        start: Opaque,
        len: usize,
        prot: c_ulong,
    },

    #[syscall(munmap)]
    Munmap {
        #[syscall(ptr(opaque))]
        addr: Opaque,
        len: usize,
    },

    #[syscall(brk)]
    Brk {
        #[syscall(ptr(opaque))]
        brk: Opaque,
    },

    #[syscall(rt_sigaction)]
    RtSigaction {
        sig: c_uint,
        #[syscall(ptr())]
        nset: kernel_sigset_t,
        #[syscall(ptr())]
        oset: kernel_sigset_t,
        sigsetsize: usize,
    },

    #[syscall(rt_sigprocmask)]
    RtSigprocmask {
        how: c_int,
        #[syscall(ptr())]
        nset: kernel_sigset_t,
        #[syscall(ptr())]
        oset: kernel_sigset_t,
        sigsetsize: usize,
    },

    #[syscall(rt_sigreturn)]
    RtSigreturn,

    #[syscall(ioctl)]
    Ioctl { fd: Fd, cmd: c_uint, arg: c_ulong },

    #[syscall(pread64)]
    Pread64 {
        fd: Fd,
        #[syscall(ptr(count=count))]
        buf: u8,
        #[syscall(private)]
        count: usize,
        pos: isize,
    },

    #[syscall(pwrite64)]
    Pwrite64 {
        fd: Fd,
        #[syscall(ptr(count=count))]
        buf: u8,
        #[syscall(private)]
        count: usize,
        pos: isize,
    },

    #[syscall(readv)]
    Readv {
        fd: Fd,
        #[syscall(ptr(count = vlen))]
        buf: iovec,
        #[syscall(private)]
        vlen: usize,
    },

    #[syscall(writev)]
    Writev {
        fd: Fd,
        #[syscall(ptr(count = vlen))]
        buf: iovec,
        #[syscall(private)]
        vlen: usize,
    },

    #[syscall(access)]
    Access {
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        mode: c_uint,
    },

    #[syscall(pipe)]
    Pipe { fildes: Fd },

    #[syscall(select)]
    Select {
        n: c_int,
        #[syscall(ptr())]
        inp: __kernel_fd_set,
        #[syscall(ptr())]
        outp: __kernel_fd_set,
        #[syscall(ptr())]
        exp: __kernel_fd_set,
        #[syscall(ptr())]
        tvp: __kernel_old_timeval,
    },

    #[syscall(sched_yield)]
    SchedYield,

    #[syscall(mremap)]
    Mremap {
        #[syscall(ptr(opaque))]
        addr: Opaque,
        old_len: usize,
        new_len: usize,
        flags: c_ulong,
        #[syscall(ptr(opaque))]
        new_addr: Opaque,
    },

    #[syscall(msync)]
    Msync {
        #[syscall(ptr(opaque))]
        start: Opaque,
        len: usize,
        flags: c_int,
    },

    #[syscall(mincore)]
    Mincore {
        #[syscall(ptr(opaque))]
        start: Opaque,
        len: usize,
        #[syscall(ptr(opaque))]
        vec: Opaque,
    },

    #[syscall(madvise)]
    Madvise {
        #[syscall(ptr(opaque))]
        start: Opaque,
        len_in: usize,
        behavior: c_int,
    },

    #[syscall(shmget)]
    Shmget {
        key: __kernel_key_t,
        sizez: usize,
        shmflg: c_int,
    },

    #[syscall(shmat)]
    Shmat {
        shmid: c_int,
        #[syscall(ptr(opaque))]
        shmaddr: Opaque,
        shmflg: c_int,
    },

    #[syscall(shmctl)]
    Shmctl {
        shmid: c_int,
        cmd: c_int,
        #[syscall(ptr())]
        buf: shmid_ds,
    },

    #[syscall(dup)]
    Dup { fildes: Fd },

    #[syscall(dup2)]
    Dup2 { oldfd: Fd, newfd: Fd },

    #[syscall(pause)]
    Pause,

    #[syscall(nanosleep)]
    Nanosleep {
        #[syscall(ptr())]
        rqtp: __kernel_timespec,
        #[syscall(ptr())]
        rmtp: __kernel_timespec,
    },

    #[syscall(getitimer)]
    Getitimer {
        which: c_int,
        #[syscall(ptr())]
        value: __kernel_old_itimerval,
    },

    #[syscall(alarm)]
    Alarm { seconds: c_uint },

    #[syscall(getpid)]
    Getpid,

    #[syscall(sendfile)]
    Sendfile {
        out_fd: Fd,
        in_fd: Fd,
        #[syscall(ptr())]
        offset: __kernel_loff_t,
        count: usize,
    },

    #[syscall(socket)]
    Socket {
        family: c_int,
        r#type: c_int,
        protocol: c_int,
    },

    #[syscall(connect)]
    Connect {
        fd: Fd,
        #[syscall(ptr(socket = addrlen))]
        addr: Opaque,
        #[syscall(private)]
        addrlen: usize,
    },

    #[syscall(accept)]
    Accept {
        fd: Fd,
        #[syscall(ptr(socket = upeer_addrlen))]
        upeer_sockaddr: SockaddrStorage,
        #[syscall(private)]
        upeer_addrlen: c_int,
    },

    #[syscall(sendto)]
    Sendto {
        fd: Fd,
        #[syscall(ptr(count = len))]
        buff: u8,
        #[syscall(private)]
        len: usize,
        flags: c_int,
        #[syscall(private)]
        addr: Opaque,
        #[syscall(private)]
        addr_len: c_int,
    },

    #[syscall(recvfrom)]
    Recvfrom {
        fd: Fd,
        #[syscall(ptr(count = size))]
        ubuf: u8,
        #[syscall(private)]
        size: usize,
        flags: c_int,
        #[syscall(private)]
        addr: Opaque,
        #[syscall(private)]
        addr_len: c_int,
    },

    #[syscall(sendmsg)]
    Sendmsg {
        fd: Fd,
        #[syscall(private)]
        msg: Opaque,
        flags: c_uint,
    },

    #[syscall(recvmsg)]
    Recvmsg {
        fd: Fd,
        #[syscall(private)]
        msg: Opaque,
        flags: c_uint,
    },

    #[syscall(shutdown)]
    Shutdown { fd: Fd, how: c_int },

    #[syscall(bind)]
    Bind {
        fd: Fd,
        #[syscall(ptr(socket = addrlen))]
        umyaddr: SockaddrStorage,
        #[syscall(private)]
        addrlen: c_int,
    },

    #[syscall(listen)]
    Listen { fd: Fd, backlog: c_int },

    #[syscall(getsockname)]
    Getsockname {
        fd: Fd,
        #[syscall(ptr())]
        usockaddr: SockaddrStorage,
        #[syscall(ptr())]
        usockaddr_len: c_int,
    },

    #[syscall(getpeername)]
    Getpeername {
        fd: Fd,
        #[syscall(ptr())]
        usockaddr: SockaddrStorage,
        #[syscall(ptr())]
        usockaddr_len: c_int,
    },

    #[syscall(socketpair)]
    Socketpair {
        family: c_int,
        r#type: c_int,
        protocol: c_int,
        #[syscall(ptr())]
        usockvec: c_int,
    },

    #[syscall(setsockopt)]
    Setsockopt {
        fd: Fd,
        level: c_int,
        optname: c_int,
        #[syscall(ptr(count = optlen))]
        optval: u8,
        #[syscall(private)]
        optlen: c_int,
    },

    #[syscall(getsockopt)]
    Getsockopt {
        fd: Fd,
        level: c_int,
        optname: c_int,
        #[syscall(private, ptr(array))]
        optval: u8,
        #[syscall(private, ptr())]
        optlen: c_int,
    },

    #[syscall(clone)]
    Clone {
        clone_flags: c_ulong,
        #[syscall(ptr(opaque))]
        newsp: Opaque,
        #[syscall(ptr())]
        parent_tid: linux_raw_sys::general::__kernel_pid_t,
        #[syscall(ptr())]
        child_tid: linux_raw_sys::general::__kernel_pid_t,
        tid: c_uint,
    },

    #[syscall(fork)]
    Fork,

    #[syscall(vfork)]
    Vfork,

    #[syscall(execve)]
    Execve {
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        #[syscall(private, ptr(opaque))]
        argv: Opaque,
        #[syscall(private, ptr(opaque))]
        envp: Opaque,
    },

    #[syscall(exit)]
    Exit { error_code: c_int },

    #[syscall(wait4)]
    Wait4 {
        upid: Pid,
        #[syscall(ptr())]
        stat_addr: c_int,
        options: c_int,
        #[syscall(ptr())]
        ru: rusage,
    },

    #[syscall(kill)]
    Kill { pid: Pid, sig: c_int },

    #[syscall(uname)]
    Uname {
        #[syscall(ptr())]
        name: old_utsname,
    },

    #[syscall(semget)]
    Semget {
        key: __kernel_key_t,
        nsems: c_int,
        semflg: c_int,
    },

    #[syscall(semop)]
    Semop {
        semid: c_int,
        #[syscall(ptr())]
        tsops: libc::sembuf,
        nsops: c_uint,
    },

    #[syscall(semctl)]
    Semctl {
        semid: c_int,
        semnum: c_int,
        cmd: c_int,
        // There doesn't appear to be a wrapper for union semun in nix, libc, or linux_raw_sys.
        #[syscall(ptr(opaque))]
        arg: Opaque,
    },

    #[syscall(shmdt)]
    Shmdt {
        #[syscall(ptr(opaque))]
        shmaddr: Opaque,
    },

    #[syscall(msgget)]
    Msgget { key: __kernel_key_t, msgflg: c_int },

    #[syscall(msgsnd)]
    Msgsnd {
        msqid: c_int,
        #[syscall(ptr(opaque))]
        msgp: Opaque,
        msgsz: usize,
        msgflg: c_int,
    },

    #[syscall(msgrcv)]
    Msgrcv {
        msqid: c_int,
        #[syscall(ptr(opaque))]
        msgp: Opaque,
        msgsz: usize,
        msgtyp: c_long,
        msgflg: c_int,
    },

    #[syscall(msgctl)]
    Msgctl {
        msqid: c_int,
        cmd: c_int,
        #[syscall(ptr(opaque))]
        buf: Opaque,
    },

    #[syscall(fcntl)]
    Fcntl { fd: Fd, cmd: c_uint, arg: c_ulong },

    #[syscall(flock)]
    Flock { fd: Fd, cmd: c_uint },

    #[syscall(fsync)]
    Fsync { fd: Fd },

    #[syscall(fdatasync)]
    Fdatasync { fd: Fd },

    #[syscall(truncate)]
    Truncate {
        #[syscall(ptr(nul_terminated))]
        path: PathBuf,
        length: c_long,
    },

    #[syscall(ftruncate)]
    Ftruncate { fd: Fd, length: c_ulong },

    #[syscall(getdents)]
    Getdents {
        fd: Fd,
        #[syscall(ptr(opaque))]
        dirent: Opaque,
        count: c_uint,
    },

    #[syscall(getcwd)]
    Getcwd {
        #[syscall(ptr(count = size))]
        buf: u8,
        #[syscall(private)]
        size: c_ulong,
    },

    #[syscall(chdir)]
    Chdir {
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
    },

    #[syscall(fchdir)]
    Fchdir { fd: Fd },

    #[syscall(rename)]
    Rename {
        #[syscall(ptr(nul_terminated))]
        oldname: PathBuf,
        #[syscall(ptr(nul_terminated))]
        newname: PathBuf,
    },

    #[syscall(mkdir)]
    Mkdir {
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        mode: c_int,
    },

    #[syscall(rmdir)]
    Rmdir {
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
    },

    #[syscall(creat)]
    Creat {
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        mode: c_int,
    },

    #[syscall(link)]
    Link {
        #[syscall(ptr(nul_terminated))]
        oldname: PathBuf,
        #[syscall(ptr(nul_terminated))]
        newname: PathBuf,
    },

    #[syscall(unlink)]
    Unlink {
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
    },

    #[syscall(symlink)]
    Symlink {
        #[syscall(ptr(nul_terminated))]
        oldname: PathBuf,
        #[syscall(ptr(nul_terminated))]
        newname: PathBuf,
    },

    #[syscall(readlink)]
    Readlink {
        #[syscall(ptr(nul_terminated))]
        path: PathBuf,
        #[syscall(ptr(opaque))]
        buf: Opaque,
        bufsiz: c_int,
    },

    #[syscall(chmod)]
    Chmod {
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        mode: __kernel_mode_t,
    },

    #[syscall(fchmod)]
    Fchmod {
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        mode: __kernel_mode_t,
    },

    #[syscall(chown)]
    Chown {
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        user: __kernel_uid_t,
        group: __kernel_gid_t,
    },

    #[syscall(fchown)]
    Fchown {
        fd: Fd,
        user: __kernel_uid_t,
        group: __kernel_gid_t,
    },

    #[syscall(lchown)]
    Lchown {
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        user: __kernel_uid_t,
        group: __kernel_gid_t,
    },

    #[syscall(umask)]
    Umask { mask: c_int },

    #[syscall(gettimeofday)]
    Gettimeofday {
        #[syscall(ptr())]
        tv: timeval,
        #[syscall(ptr())]
        tz: timezone,
    },

    #[syscall(getrlimit)]
    Getrlimit {
        resource: c_uint,
        #[syscall(ptr())]
        rlim: rlimit,
    },

    #[syscall(getrusage)]
    Getrusage {
        who: c_int,
        #[syscall(ptr())]
        ru: rusage,
    },

    #[syscall(sysinfo)]
    Sysinfo {
        #[syscall(ptr())]
        info: sysinfo,
    },

    #[syscall(times)]
    Times {
        #[syscall(ptr())]
        tbuf: libc::tms,
    },

    #[syscall(ptrace)]
    Ptrace {
        request: c_long,
        pid: Pid,
        #[syscall(ptr(opaque))]
        addr: Opaque,
        #[syscall(ptr(opaque))]
        data: Opaque,
    },

    #[syscall(getuid)]
    Getuid,

    #[syscall(syslog)]
    Syslog {
        r#type: c_int,
        #[syscall(ptr(count = len))]
        buf: u8,
        #[syscall(private)]
        len: c_int,
    },

    #[syscall(getgid)]
    Getgid,

    #[syscall(setuid)]
    Setuid { uid: __kernel_uid_t },

    #[syscall(setgid)]
    Setgid { gid: __kernel_gid_t },

    #[syscall(geteuid)]
    Geteuid,

    #[syscall(getegid)]
    Getegid,

    #[syscall(setpgid)]
    Setpgid { pid: Pid, pgid: Pid },

    #[syscall(getppid)]
    Getppid,

    #[syscall(getpgrp)]
    Getpgrp,

    #[syscall(setsid)]
    Setsid,

    #[syscall(setreuid)]
    Setreuid {
        ruid: __kernel_uid_t,
        euid: __kernel_uid_t,
    },

    #[syscall(setregid)]
    Setregid {
        rgid: __kernel_gid_t,
        egid: __kernel_gid_t,
    },

    #[syscall(getgroups)]
    Getgroups {
        #[syscall(private)]
        gidsetsize: usize,
        #[syscall(ptr(count = gidsetsize))]
        grouplist: __kernel_gid_t,
    },

    #[syscall(setgroups)]
    Setgroups {
        #[syscall(private)]
        gidsetsize: usize,
        #[syscall(ptr(count = gidsetsize))]
        grouplist: __kernel_gid_t,
    },

    #[syscall(setresuid)]
    Setresuid {
        ruid: __kernel_uid_t,
        euid: __kernel_uid_t,
        suid: __kernel_uid_t,
    },

    #[syscall(getresuid)]
    Getresuid {
        #[syscall(ptr())]
        ruid: __kernel_uid_t,
        #[syscall(ptr())]
        euid: __kernel_uid_t,
        #[syscall(ptr())]
        suid: __kernel_uid_t,
    },

    #[syscall(setresgid)]
    Setresgid {
        rgid: __kernel_gid_t,
        egid: __kernel_gid_t,
        sgid: __kernel_gid_t,
    },

    #[syscall(getresgid)]
    Getresgid {
        #[syscall(ptr())]
        rgid: __kernel_gid_t,
        #[syscall(ptr())]
        egid: __kernel_gid_t,
        #[syscall(ptr())]
        sgid: __kernel_gid_t,
    },

    #[syscall(getpgid)]
    Getpgid { pid: Pid },

    #[syscall(setfsuid)]
    Setfsuid { uid: __kernel_uid_t },

    #[syscall(setfsgid)]
    Setfsgid { gid: __kernel_gid_t },

    #[syscall(getsid)]
    Getsid { pid: Pid },

    #[syscall(capget)]
    Capget {
        #[syscall(ptr())]
        header: cap_user_header_t,
        #[syscall(ptr())]
        dataptr: cap_user_data_t,
    },

    #[syscall(capset)]
    Capset {
        #[syscall(ptr())]
        header: cap_user_header_t,
        #[syscall(ptr())]
        data: cap_user_data_t,
    },

    #[syscall(rt_sigpending)]
    RtSigpending {
        #[syscall(ptr())]
        uset: sigset_t,
        sigsetsize: usize,
    },

    #[syscall(rt_sigtimedwait)]
    RtSigtimedWait {
        #[syscall(ptr())]
        uthese: sigset_t,
        #[syscall(ptr())]
        uinfo: siginfo_t,
        #[syscall(ptr())]
        uts: __kernel_timespec,
        sigsetsize: usize,
    },

    #[syscall(rt_sigqueueinfo)]
    RtSigqueueinfo {
        pid: Pid,
        sig: c_int,
        #[syscall(ptr())]
        uinfo: siginfo_t,
    },

    #[syscall(rt_sigsuspend)]
    RtSigsuspend {
        #[syscall(ptr())]
        unewset: sigset_t,
        sigsetsize: usize,
    },

    #[syscall(sigaltstack)]
    Sigaltstack {
        #[syscall(ptr())]
        uss: stack_t,
        #[syscall(ptr())]
        uoss: stack_t,
    },

    #[syscall(utime)]
    Utime {
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        #[syscall(ptr())]
        times: utimbuf,
    },

    #[syscall(mknod)]
    Mknod {
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        mode: c_ushort,
        dev: c_uint,
    },

    #[syscall(personality)]
    Personality { personality: c_uint },

    #[syscall(ustat)]
    Ustat {
        dev: c_uint,
        #[syscall(ptr())]
        ubuf: ustat,
    },

    #[syscall(statfs)]
    Statfs {
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        #[syscall(ptr())]
        buf: statfs,
    },

    #[syscall(fstatfs)]
    Fstatfs {
        fd: Fd,
        #[syscall(ptr())]
        buf: statfs,
    },

    #[syscall(sysfs)]
    Sysfs {
        option: c_int,
        arg1: c_ulong,
        arg2: c_ulong,
    },

    #[syscall(getpriority)]
    Getpriority { which: c_int, who: c_int },

    #[syscall(setpriority)]
    Setpriority {
        which: c_int,
        who: c_int,
        niceval: c_int,
    },

    #[syscall(sched_setparam)]
    SchedSetparam {
        pid: Pid,
        #[syscall(ptr())]
        param: sched_param,
    },

    #[syscall(sched_getparam)]
    SchedGetparam {
        pid: Pid,
        #[syscall(ptr())]
        param: sched_param,
    },

    #[syscall(sched_setscheduler)]
    SchedSetscheduler {
        pid: Pid,
        policy: c_int,
        #[syscall(ptr())]
        param: sched_param,
    },

    #[syscall(sched_getscheduler)]
    SchedGetscheduler { pid: Pid },

    #[syscall(sched_get_priority_max)]
    SchedGetPriorityMax { policy: c_int },

    #[syscall(sched_get_priority_min)]
    SchedGetPriorityMin { policy: c_int },

    #[syscall(sched_rr_get_interval)]
    SchedRrGetInterval {
        pid: Pid,
        #[syscall(ptr())]
        interval: __kernel_timespec,
    },

    #[syscall(mlock)]
    Mlock {
        #[syscall(ptr(opaque))]
        start: Opaque,
        len: usize,
    },

    #[syscall(munlock)]
    Munlock {
        #[syscall(ptr(opaque))]
        start: Opaque,
        len: usize,
    },

    #[syscall(mlockall)]
    Mlockall { flags: c_int },

    #[syscall(munlockall)]
    Munlockall,

    #[syscall(vhangup)]
    Vhangup,

    #[syscall(modify_ldt)]
    ModifyLdt {
        func: c_int,
        #[syscall(ptr(opaque))]
        ptr: Opaque,
        bytecount: c_ulong,
    },

    #[syscall(pivot_root)]
    PivotRoot {
        #[syscall(ptr(nul_terminated))]
        new_root: PathBuf,
        #[syscall(ptr(nul_terminated))]
        put_old: PathBuf,
    },

    #[syscall(prctl)]
    Prctl {
        option: c_int,
        arg2: c_ulong,
        arg3: c_ulong,
        arg4: c_ulong,
        arg5: c_ulong,
    },

    #[syscall(arch_prctl)]
    ArchPrctl { option: c_int, arg2: c_ulong },

    #[syscall(adjtimex)]
    Adjtimex {
        #[syscall(ptr())]
        txc_p: timex,
    },

    #[syscall(setrlimit)]
    Setrlimit {
        resource: c_int,
        #[syscall(ptr())]
        rlim: rlimit,
    },

    #[syscall(chroot)]
    Chroot {
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
    },

    #[syscall(sync)]
    Sync,

    #[syscall(acct)]
    Acct {
        #[syscall(ptr(nul_terminated))]
        name: PathBuf,
    },

    #[syscall(settimeofday)]
    Settimeofday {
        #[syscall(ptr())]
        tv: __kernel_old_timeval,
        #[syscall(ptr())]
        tz: timezone,
    },

    #[syscall(mount)]
    Mount {
        #[syscall(ptr(nul_terminated))]
        dev_name: PathBuf,
        #[syscall(ptr(nul_terminated))]
        dir_name: PathBuf,
        #[syscall(ptr(nul_terminated))]
        r#type: OsString,
        flags: c_ulong,
        #[syscall(ptr(opaque))]
        data: Opaque,
    },

    #[syscall(umount2)]
    Umount {
        #[syscall(ptr(nul_terminated))]
        name: PathBuf,
        flags: c_int,
    },

    #[syscall(swapon)]
    Swapon {
        #[syscall(ptr(nul_terminated))]
        specialfile: PathBuf,
        swap_flags: c_int,
    },

    #[syscall(swapoff)]
    Swapoff {
        #[syscall(ptr(nul_terminated))]
        specialfile: PathBuf,
    },

    #[syscall(reboot)]
    Reboot {
        magic1: c_int,
        magic2: c_int,
        cmd: c_uint,
        #[syscall(ptr(opaque))]
        arg: Opaque,
    },

    #[syscall(sethostname)]
    Sethostname {
        #[syscall(ptr(count = len))]
        name: OsString,
        #[syscall(private)]
        len: c_int,
    },

    #[syscall(setdomainname)]
    Setdomainname {
        #[syscall(ptr(count = len))]
        name: OsString,
        #[syscall(private)]
        len: c_int,
    },

    #[syscall(iopl)]
    Iopl { level: c_uint },

    #[syscall(ioperm)]
    Ioperm {
        from: c_ulong,
        num: c_ulong,
        turn_on: c_int,
    },

    #[syscall(init_module)]
    InitModule {
        #[syscall(ptr(count = len))]
        umod: u8,
        #[syscall(private)]
        len: c_ulong,
        #[syscall(ptr(nul_terminated))]
        uargs: OsString,
    },

    #[syscall(delete_module)]
    DeleteModule {
        #[syscall(ptr(nul_terminated))]
        name_user: OsString,
        flags: c_uint,
    },

    #[syscall(quotactl)]
    Quotactl {
        cmd: c_uint,
        #[syscall(ptr(nul_terminated))]
        special: PathBuf,
        id: __kernel_uid32_t,
        #[syscall(ptr(opaque))]
        addr: Opaque,
    },

    #[syscall(gettid)]
    Gettid,

    #[syscall(readahead)]
    Readahead {
        fd: Fd,
        offset: __kernel_loff_t,
        count: usize,
    },

    #[syscall(setxattr)]
    Setxattr {
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        #[syscall(ptr(nul_terminated))]
        name: OsString,
        #[syscall(ptr(count = size))]
        value: u8,
        #[syscall(private)]
        size: usize,
        flags: c_int,
    },

    #[syscall(lsetxattr)]
    Lsetxattr {
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        #[syscall(ptr(nul_terminated))]
        name: OsString,
        #[syscall(ptr(count = size))]
        value: u8,
        #[syscall(private)]
        size: usize,
        flags: c_int,
    },

    #[syscall(fsetxattr)]
    Fsetxattr {
        fd: Fd,
        #[syscall(ptr(nul_terminated))]
        name: OsString,
        #[syscall(ptr(count = size))]
        value: u8,
        #[syscall(private)]
        size: usize,
        flags: c_int,
    },

    #[syscall(getxattr)]
    Getxattr {
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        #[syscall(ptr(nul_terminated))]
        name: OsString,
        #[syscall(ptr(count = size))]
        value: u8,
        #[syscall(private)]
        size: usize,
    },

    #[syscall(lgetxattr)]
    Lgetxattr {
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        #[syscall(ptr(nul_terminated))]
        name: OsString,
        #[syscall(ptr(count = size))]
        value: u8,
        #[syscall(private)]
        size: usize,
    },

    #[syscall(fgetxattr)]
    Fgetxattr {
        fd: Fd,
        #[syscall(ptr(nul_terminated))]
        name: OsString,
        #[syscall(ptr(count = size))]
        value: u8,
        #[syscall(private)]
        size: usize,
    },

    #[syscall(listxattr)]
    Listxattr {
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        #[syscall(ptr(count = size))]
        list: u8,
        #[syscall(private)]
        size: usize,
    },

    #[syscall(llistxattr)]
    Llistxattr {
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        #[syscall(ptr(count = size))]
        list: u8,
        #[syscall(private)]
        size: usize,
    },

    #[syscall(flistxattr)]
    Flistxattr {
        fd: Fd,
        #[syscall(ptr(count = size))]
        list: u8,
        #[syscall(private)]
        size: usize,
    },

    #[syscall(removexattr)]
    Removexattr {
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        #[syscall(ptr(nul_terminated))]
        name: OsString,
    },

    #[syscall(lremovexattr)]
    Lremovexattr {
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        #[syscall(ptr(nul_terminated))]
        name: OsString,
    },

    #[syscall(fremovexattr)]
    Fremovexattr {
        fd: Fd,
        #[syscall(ptr(nul_terminated))]
        name: OsString,
    },

    #[syscall(tkill)]
    Tkill { pid: Pid, sig: c_int },

    #[syscall(time)]
    Time {
        #[syscall(ptr())]
        tloc: c_long,
    },

    #[syscall(futex)]
    Futex {
        #[syscall(ptr())]
        uaddr: u32,
        op: c_int,
        val: u32,
        #[syscall(ptr())]
        utime: __kernel_timespec,
        #[syscall(ptr())]
        uaddr2: u32,
        val3: u32,
    },

    #[syscall(sched_setaffinity)]
    SchedSetaffinity {
        pid: Pid,
        #[syscall(private)]
        len: c_uint,
        #[syscall(ptr(count = len))]
        user_mask_ptr: cpu_set_t,
    },

    #[syscall(sched_getaffinity)]
    SchedGetaffinity {
        pid: Pid,
        #[syscall(private)]
        len: c_uint,
        #[syscall(ptr(count = len))]
        user_mask_ptr: cpu_set_t,
    },

    #[syscall(io_setup)]
    IoSetup {
        nr_events: c_uint,
        #[syscall(ptr())]
        ctxp: aio_context,
    },

    #[syscall(io_destroy)]
    IoDestroy { ctx: aio_context },

    #[syscall(io_getevents)]
    IoGetevents {
        ctx_id: aio_context,
        min_nr: c_long,
        #[syscall(private)]
        nr: c_long,
        #[syscall(ptr(count = nr))]
        events: io_event,
        #[syscall(ptr())]
        timeout: __kernel_timespec,
    },

    #[syscall(io_submit)]
    IoSubmit {
        ctx_id: aio_context,
        #[syscall(private)]
        nr: c_long,
        #[syscall(private, ptr(count = nr))]
        iocbpp: Opaque,
    },

    #[syscall(io_cancel)]
    IoCancel {
        ctx_id: aio_context,
        #[syscall(ptr())]
        iocb: iocb,
        #[syscall(ptr())]
        result: io_event,
    },

    #[syscall(epoll_create)]
    EpollCreate { size: c_int },

    #[syscall(remap_file_pages)]
    RemapFilePages {
        #[syscall(ptr(opaque))]
        start: Opaque,
        size: c_ulong,
        prot: c_ulong,
        pgoff: c_ulong,
        flags: c_ulong,
    },

    #[syscall(getdents64)]
    Getdents64 {
        fd: Fd,
        #[syscall(ptr(count = count))]
        dirent: linux_dirent64,
        count: c_uint,
    },

    #[syscall(set_tid_address)]
    SetTidAddress {
        #[syscall(ptr())]
        tidptr: c_int,
    },

    #[syscall(restart_syscall)]
    RestartSyscall,

    #[syscall(semtimedop)]
    Semtimedop {
        semid: c_int,
        #[syscall(ptr(count = nsops))]
        tsops: sembuf,
        #[syscall(private)]
        nsops: c_uint,
        #[syscall(ptr())]
        timeout: __kernel_timespec,
    },

    #[syscall(fadvise64)]
    Fadvise64 {
        fd: Fd,
        offset: __kernel_loff_t,
        len: usize,
        advice: c_int,
    },

    #[syscall(timer_create)]
    TimerCreate {
        which_clock: __kernel_clockid_t,
        #[syscall(ptr())]
        timer_event_spec: sigevent,
        #[syscall(ptr())]
        created_timer_id: __kernel_timer_t,
    },

    #[syscall(timer_settime)]
    TimerSettime {
        timer_id: __kernel_timer_t,
        flags: c_int,
        #[syscall(ptr())]
        new_setting: __kernel_itimerspec,
        #[syscall(ptr())]
        old_setting: __kernel_itimerspec,
    },

    #[syscall(timer_gettime)]
    TimerGettime {
        timer_id: __kernel_timer_t,
        #[syscall(ptr())]
        setting: __kernel_itimerspec,
    },

    #[syscall(timer_getoverrun)]
    TimerGetoverrun { timer_id: __kernel_timer_t },

    #[syscall(timer_delete)]
    TimerDelete { timer_id: __kernel_timer_t },

    #[syscall(clock_settime)]
    ClockSettime {
        which_clock: __kernel_clockid_t,
        #[syscall(ptr())]
        tp: __kernel_timespec,
    },

    #[syscall(clock_gettime)]
    ClockGettime {
        which_clock: __kernel_clockid_t,
        #[syscall(ptr())]
        tp: __kernel_timespec,
    },

    #[syscall(clock_getres)]
    ClockGetres {
        which_clock: __kernel_clockid_t,
        #[syscall(ptr())]
        tp: __kernel_timespec,
    },

    #[syscall(clock_nanosleep)]
    ClockNanosleep {
        which_clock: __kernel_clockid_t,
        flags: c_int,
        #[syscall(ptr())]
        rqtp: __kernel_timespec,
        #[syscall(ptr())]
        rmtp: __kernel_timespec,
    },

    #[syscall(exit_group)]
    ExitGroup { error_code: c_int },

    #[syscall(epoll_wait)]
    EpollWait {
        epfd: Fd,
        #[syscall(ptr(count = maxevents))]
        events: epoll_event,
        #[syscall(private)]
        maxevents: c_int,
        timeout: c_int,
    },

    #[syscall(epoll_ctl)]
    EpollCtl {
        epfd: Fd,
        op: c_int,
        fd: Fd,
        #[syscall(ptr())]
        event: epoll_event,
    },

    #[syscall(tgkill)]
    Tgkill { tgid: Pid, pid: Pid, sig: c_int },

    #[syscall(utimes)]
    Utimes {
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        #[syscall(ptr())]
        utimes: __kernel_old_timeval,
    },

    #[syscall(mbind)]
    Mbind {
        #[syscall(ptr(opaque))]
        start: Opaque,
        len: c_ulong,
        mode: c_ulong,
        #[syscall(ptr())]
        nmask: c_ulong,
        maxnode: c_ulong,
        flags: c_uint,
    },

    #[syscall(set_mempolicy)]
    SetMempolicy {
        mode: c_int,
        #[syscall(ptr())]
        nmask: c_ulong,
        maxnode: c_ulong,
    },

    #[syscall(get_mempolicy)]
    GetMempolicy {
        #[syscall(ptr())]
        policy: c_int,
        #[syscall(ptr())]
        nmask: c_ulong,
        maxnode: c_ulong,
        #[syscall(ptr(opaque))]
        addr: Opaque,
        flags: c_ulong,
    },

    #[syscall(mq_open)]
    MqOpen {
        #[syscall(ptr(nul_terminated))]
        u_name: OsString,
        oflag: c_int,
        mode: c_ushort,
        #[syscall(ptr())]
        u_attr: mq_attr,
    },

    #[syscall(mq_unlink)]
    MqUnlink {
        #[syscall(ptr(nul_terminated))]
        u_name: OsString,
    },

    #[syscall(mq_timedsend)]
    MqTimedsend {
        mqdes: mqd_t,
        #[syscall(ptr(count = msg_len))]
        u_msg_ptr: u8,
        #[syscall(private)]
        msg_len: usize,
        msg_prio: c_uint,
        #[syscall(ptr())]
        u_abs_timeout: __kernel_timespec,
    },

    #[syscall(mq_timedreceive)]
    MqTimedreceive {
        mqdes: mqd_t,
        #[syscall(ptr(count = msg_len))]
        u_msg_ptr: u8,
        #[syscall(private)]
        msg_len: usize,
        #[syscall(ptr())]
        u_msg_prio: c_uint,
        #[syscall(ptr())]
        u_abs_timeout: __kernel_timespec,
    },

    #[syscall(mq_notify)]
    MqNotify {
        mqdes: mqd_t,
        #[syscall(ptr())]
        u_notification: sigevent,
    },

    #[syscall(mq_getsetattr)]
    MqGetsetattr {
        mqdes: mqd_t,
        #[syscall(ptr())]
        u_mqstat: mq_attr,
        #[syscall(ptr())]
        u_omqstat: mq_attr,
    },

    #[syscall(kexec_load)]
    KexecLoad {
        entry: c_ulong,
        #[syscall(private)]
        nr_segments: c_ulong,
        #[syscall(ptr(count = nr_segments))]
        segments: kexec_segment,
        flags: c_ulong,
    },

    #[syscall(waitid)]
    Waitid {
        which: c_int,
        upid: Pid,
        #[syscall(ptr())]
        infop: siginfo,
        options: c_int,
        #[syscall(ptr())]
        ru: rusage,
    },

    #[syscall(add_key)]
    AddKey {
        #[syscall(ptr(nul_terminated))]
        _type: OsString,
        #[syscall(ptr(nul_terminated))]
        _description: OsString,
        #[syscall(ptr(count = plen))]
        _payload: u8,
        #[syscall(private)]
        plen: usize,
        ringid: i32,
    },

    #[syscall(request_key)]
    RequestKey {
        #[syscall(ptr(nul_terminated))]
        _type: OsString,
        #[syscall(ptr(nul_terminated))]
        _description: OsString,
        #[syscall(ptr(nul_terminated))]
        _callout_info: OsString,
        destringid: i32,
    },

    #[syscall(keyctl)]
    Keyctl {
        option: c_int,
        arg2: c_ulong,
        arg3: c_ulong,
        arg4: c_ulong,
        arg5: c_ulong,
    },

    #[syscall(ioprio_set)]
    IoprioSet {
        which: c_int,
        who: c_int,
        ioprio: c_int,
    },

    #[syscall(ioprio_get)]
    IoprioGet { which: c_int, who: c_int },

    #[syscall(inotify_init)]
    IonotifyInit,

    #[syscall(inotify_add_watch)]
    InotifyAddWatch {
        fd: Fd,
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        mask: u32,
    },

    #[syscall(inotify_rm_watch)]
    InotifyRmWatch { fd: Fd, wd: i32 },

    #[syscall(migrate_pages)]
    MigratePages {
        pid: Pid,
        maxnode: c_ulong,
        #[syscall(ptr())]
        old_nodes: c_ulong,
        #[syscall(ptr())]
        new_nodes: c_long,
    },

    #[syscall(openat)]
    Openat {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        flags: c_int,
        mode: c_ushort,
    },

    #[syscall(mkdirat)]
    Mkdirat {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        mode: c_ushort,
    },

    #[syscall(mknodat)]
    Mknodat {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        mode: c_ushort,
        dev: c_uint,
    },

    #[syscall(fchownat)]
    Fchownat {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        user: __kernel_uid_t,
        group: __kernel_gid_t,
        flag: c_int,
    },

    #[syscall(futimesat)]
    Futimesat {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        #[syscall(ptr())]
        utimes: __kernel_old_timeval,
    },

    #[syscall(newfstatat)]
    Newfstatat {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        #[syscall(ptr())]
        statbuf: stat,
        flag: c_int,
    },

    #[syscall(unlinkat)]
    Unlinkat {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        flag: c_int,
    },

    #[syscall(renameat)]
    Renameat {
        olddfd: Fd,
        #[syscall(ptr(nul_terminated))]
        oldname: PathBuf,
        newdfd: Fd,
        #[syscall(ptr(nul_terminated))]
        newname: PathBuf,
    },

    #[syscall(linkat)]
    Linkat {
        olddfd: Fd,
        #[syscall(ptr(nul_terminated))]
        oldname: PathBuf,
        newdfd: Fd,
        #[syscall(ptr(nul_terminated))]
        newname: PathBuf,
        flags: c_int,
    },

    #[syscall(symlinkat)]
    Symlinkat {
        #[syscall(ptr(nul_terminated))]
        oldname: PathBuf,
        newdfd: Fd,
        #[syscall(ptr(nul_terminated))]
        newname: PathBuf,
    },

    #[syscall(readlinkat)]
    Readlinkat {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
        #[syscall(ptr(count = bufsiz))]
        buf: u8,
        #[syscall(private)]
        bufsiz: c_int,
    },

    #[syscall(fchmodat)]
    Fchmodat {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        mode: c_ushort,
    },

    #[syscall(faccessat)]
    Faccessat {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        mode: c_int,
    },

    #[syscall(pselect6)]
    Pselect6 {
        n: c_int,
        #[syscall(ptr())]
        inp: __kernel_fd_set,
        #[syscall(ptr())]
        outp: __kernel_fd_set,
        #[syscall(ptr())]
        exp: __kernel_fd_set,
        #[syscall(ptr())]
        tsp: __kernel_timespec,
        #[syscall(ptr())]
        sigmask: sigset_t,
    },

    #[syscall(ppoll)]
    Ppoll {
        #[syscall(ptr(count = nfds))]
        ufds: pollfd,
        #[syscall(private)]
        nfds: c_uint,
        #[syscall(ptr())]
        tsp: __kernel_timespec,
        #[syscall(ptr())]
        sigmask: sigset_t,
        sigsetsize: usize,
    },

    #[syscall(unshare)]
    Unshare { unshare_flags: c_ulong },

    #[syscall(set_robust_list)]
    SetRobustList {
        #[syscall(ptr())]
        head: robust_list_head,
        len: usize,
    },

    #[syscall(get_robust_list)]
    GetRobustList {
        pid: Pid,
        #[syscall(private)]
        head_ptr: Opaque,
        #[syscall(ptr())]
        len_ptr: usize,
    },

    #[syscall(splice)]
    Splice {
        fd_in: Fd,
        #[syscall(ptr())]
        off_in: __kernel_loff_t,
        fd_out: Fd,
        #[syscall(ptr())]
        off_out: __kernel_loff_t,
        len: usize,
        flags: c_uint,
    },

    #[syscall(tee)]
    Tee {
        fdin: Fd,
        fdout: Fd,
        len: usize,
        flags: c_uint,
    },

    #[syscall(sync_file_range)]
    SyncFileRange {
        fd: Fd,
        offset: __kernel_loff_t,
        nbytes: __kernel_loff_t,
        flags: c_uint,
    },

    #[syscall(vmsplice)]
    Vmsplice {
        fd: Fd,
        #[syscall(ptr(count = nr_segs))]
        uiov: iovec,
        #[syscall(private)]
        nr_segs: c_ulong,
        flags: c_uint,
    },

    #[syscall(move_pages)]
    MovePages {
        pid: Pid,
        #[syscall(private)]
        nr_pages: c_ulong,
        #[syscall(ptr(count = nr_pages))]
        pages: Opaque,
        #[syscall(ptr(count = nr_pages))]
        nodes: c_int,
        #[syscall(ptr(count = nr_pages))]
        status: c_int,
        flags: c_int,
    },

    #[syscall(utimensat)]
    Utimensat {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        #[syscall(ptr())]
        utimes: __kernel_timespec,
        flags: c_int,
    },

    #[syscall(epoll_pwait)]
    EpollPwait {
        epfd: Fd,
        #[syscall(ptr(count = maxevents))]
        events: epoll_event,
        #[syscall(private)]
        maxevents: c_int,
        timeout: c_int,
        #[syscall(ptr())]
        sigmask: sigset_t,
        sigsetsize: usize,
    },

    #[syscall(signalfd)]
    Signalfd {
        ufd: Fd,
        #[syscall(ptr())]
        user_mask: sigset_t,
        sizemask: usize,
    },

    #[syscall(timerfd_create)]
    TimerfdCreate { clockid: c_int, flags: c_int },

    #[syscall(eventfd)]
    Eventfd { count: c_uint },

    #[syscall(fallocate)]
    Fallocate {
        fd: Fd,
        mode: c_int,
        offset: __kernel_loff_t,
        len: __kernel_loff_t,
    },

    #[syscall(timerfd_settime)]
    TimerfdSettime {
        ufd: Fd,
        flags: c_int,
        #[syscall(ptr())]
        utmr: __kernel_itimerspec,
        #[syscall(ptr())]
        otmr: __kernel_itimerspec,
    },

    #[syscall(timerfd_gettime)]
    TimerfdGettime {
        ufd: Fd,
        #[syscall(ptr())]
        otmr: __kernel_itimerspec,
    },

    #[syscall(accept4)]
    Accept4 {
        fd: Fd,
        #[syscall(ptr())]
        upeer_sockaddr: sockaddr,
        #[syscall(ptr())]
        upeer_addrlen: c_int,
        flags: c_int,
    },

    #[syscall(signalfd4)]
    Signalfd4 {
        ufd: Fd,
        #[syscall(ptr())]
        user_mask: sigset_t,
        sizemask: usize,
        flags: c_int,
    },

    #[syscall(eventfd2)]
    Eventfd2 { count: c_uint, flags: c_int },

    #[syscall(epoll_create1)]
    EpollCreate1 { flags: c_int },

    #[syscall(dup3)]
    Dup3 { oldfd: Fd, newfd: Fd, flags: c_int },

    #[syscall(pipe2)]
    Pipe2 {
        #[syscall(private)]
        fildes: Opaque,
        flags: c_int,
    },

    #[syscall(inotify_init1)]
    InotifyInit1 { flags: c_int },

    #[syscall(preadv)]
    Preadv {
        fd: Fd,
        #[syscall(ptr(count = vlen))]
        vec: iovec,
        #[syscall(private)]
        vlen: c_ulong,
        pos_l: c_ulong,
        pos_h: c_ulong,
    },

    #[syscall(pwritev)]
    Pwritev {
        fd: Fd,
        #[syscall(ptr(count = vlen))]
        vec: iovec,
        #[syscall(private)]
        vlen: c_ulong,
        pos_l: c_ulong,
        pos_h: c_ulong,
    },

    #[syscall(rt_tgsigqueueinfo)]
    RtTgsigqueueinfo {
        tgid: Pid,
        pid: Pid,
        sig: c_int,
        #[syscall(ptr())]
        uinfo: siginfo,
    },

    #[syscall(perf_event_open)]
    PerfEventOpen {
        // XXX: The perf-event-open crate has good bindings to the perf_event_attr struct, but
        // they're not exported.
        #[syscall(ptr(opaque))]
        attr_uptr: Opaque,
        pid: Pid,
        cpu: c_int,
        group_fd: Fd,
        flags: c_ulong,
    },

    #[syscall(recvmmsg)]
    Recvmmsg {
        fd: Fd,
        #[syscall(ptr(count = vlen))]
        mmsg: mmsghdr,
        #[syscall(private)]
        vlen: c_uint,
        flags: c_uint,
        #[syscall(ptr())]
        timeout: __kernel_timespec,
    },

    #[syscall(fanotify_init)]
    FanotifyInit {
        flags: c_uint,
        event_f_flags: c_uint,
    },

    #[syscall(fanotify_mark)]
    FanotifyMark {
        fanotify_fd: Fd,
        flags: c_uint,
        mask: u64,
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        pathname: PathBuf,
    },

    #[syscall(prlimit64)]
    Prlimit64 {
        pid: Pid,
        resource: c_uint,
        #[syscall(ptr())]
        new_rlim: rlimit64,
        #[syscall(ptr())]
        old_rlim: rlimit64,
    },

    #[syscall(name_to_handle_at)]
    NameToHandleAt {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        name: PathBuf,
        #[syscall(private)]
        handle: Opaque,
        #[syscall(ptr())]
        mnt_id: c_int,
        flag: c_int,
    },

    #[syscall(open_by_handle_at)]
    OpenByHandleAt {
        mountdirfd: Fd,
        #[syscall(private)]
        handle: Opaque,
        flags: c_int,
    },

    #[syscall(clock_adjtime)]
    ClockAdjtime {
        which_clock: __kernel_clockid_t,
        #[syscall(ptr())]
        utx: timex,
    },

    #[syscall(syncfs)]
    Syncfs { fd: Fd },

    #[syscall(sendmmsg)]
    Sendmmsg {
        fd: Fd,
        #[syscall(ptr(count = vlen))]
        mmsg: mmsghdr,
        #[syscall(private)]
        vlen: c_uint,
        flags: c_uint,
    },

    #[syscall(setns)]
    Setns { fd: Fd, flags: c_int },

    #[syscall(getcpu)]
    Getcpu {
        #[syscall(ptr())]
        cpup: c_uint,
        #[syscall(ptr())]
        nodep: c_uint,
        #[syscall(ptr(opaque))]
        unused: Opaque,
    },

    #[syscall(process_vm_readv)]
    ProcessVmReadv {
        pid: Pid,
        #[syscall(ptr(count = liovcnt))]
        lvec: iovec,
        #[syscall(private)]
        liovcnt: c_ulong,
        #[syscall(ptr(count = riovcnt))]
        rvec: iovec,
        #[syscall(private)]
        riovcnt: c_ulong,
        flags: c_ulong,
    },

    #[syscall(process_vm_writev)]
    ProcessVmWritev {
        pid: Pid,
        #[syscall(ptr(count = liovcnt))]
        lvec: iovec,
        #[syscall(private)]
        liovcnt: c_ulong,
        #[syscall(ptr(count = riovcnt))]
        rvec: iovec,
        #[syscall(private)]
        riovcnt: c_ulong,
        flags: c_ulong,
    },

    #[syscall(kcmp)]
    Kcmp {
        pid1: Pid,
        pid2: Pid,
        r#type: c_int,
        idx1: c_ulong,
        idx2: c_ulong,
    },

    #[syscall(finit_module)]
    FinitModule {
        fd: Fd,
        #[syscall(ptr(nul_terminated))]
        uargs: OsString,
        flags: c_int,
    },

    #[syscall(sched_setattr)]
    SchedSetattr {
        pid: Pid,
        #[syscall(ptr())]
        uattr: sched_attr,
        flags: c_int,
    },

    #[syscall(sched_getattr)]
    SchedGetattr {
        pid: Pid,
        #[syscall(ptr())]
        uattr: sched_attr,
        usize: c_uint,
        flags: c_int,
    },

    #[syscall(renameat2)]
    Renameat2 {
        olddfd: Fd,
        #[syscall(ptr(nul_terminated))]
        oldname: PathBuf,
        newdfd: Fd,
        #[syscall(ptr(nul_terminated))]
        newname: PathBuf,
        flags: c_uint,
    },

    #[syscall(seccomp)]
    Seccomp {
        op: c_uint,
        flags: c_uint,
        #[syscall(ptr(opaque))]
        uargs: Opaque,
    },

    #[syscall(getrandom)]
    Getrandom {
        #[syscall(ptr(count = len))]
        ubuf: u8,
        #[syscall(private)]
        len: usize,
        flags: c_uint,
    },

    #[syscall(memfd_create)]
    MemfdCreate {
        #[syscall(ptr(nul_terminated))]
        uname: PathBuf,
        flags: c_uint,
    },

    #[syscall(kexec_file_load)]
    KexecFileLoad {
        kernel_fd: Fd,
        initrd_fd: Fd,
        #[syscall(private)]
        cmdline_len: c_ulong,
        #[syscall(ptr(count = cmdline_len))]
        cmdline_ptr: u8,
        flags: c_ulong,
    },

    #[syscall(bpf)]
    Bpf {
        cmd: c_int,
        #[syscall(ptr(opaque))]
        uattr: Opaque,
        size: c_uint,
    },

    #[syscall(execveat)]
    Execveat {
        fd: Fd,
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        #[syscall(private)]
        argv: Opaque,
        #[syscall(private)]
        envp: Opaque,
        flags: c_int,
    },

    #[syscall(userfaultfd)]
    Userfaultfd { flags: c_int },

    #[syscall(membarrier)]
    Membarrier {
        cmd: c_int,
        flags: c_uint,
        cpu_id: c_int,
    },

    #[syscall(mlock2)]
    Mlock2 {
        start: Opaque,
        len: usize,
        flags: c_int,
    },

    #[syscall(copy_file_range)]
    CopyFileRange {
        fd_in: Fd,
        #[syscall(ptr())]
        off_in: __kernel_loff_t,
        fd_out: Fd,
        #[syscall(ptr())]
        off_out: __kernel_loff_t,
        len: usize,
        flags: c_uint,
    },

    #[syscall(preadv2)]
    Preadv2 {
        fd: Fd,
        #[syscall(ptr(count = vlen))]
        vec: iovec,
        #[syscall(private)]
        vlen: c_ulong,
        pos_l: c_ulong,
        pos_h: c_ulong,
        flags: __kernel_rwf_t,
    },

    #[syscall(pwritev2)]
    Pwritev2 {
        fd: Fd,
        #[syscall(ptr(count = vlen))]
        vec: iovec,
        #[syscall(private)]
        vlen: c_ulong,
        pos_l: c_ulong,
        pos_h: c_ulong,
        flags: __kernel_rwf_t,
    },

    #[syscall(pkey_mprotect)]
    PkeyMprotect {
        start: Opaque,
        len: usize,
        prot: c_ulong,
        pkey: c_int,
    },

    #[syscall(pkey_alloc)]
    PkeyAlloc { flags: c_ulong, init_val: c_ulong },

    #[syscall(pkey_free)]
    PkeyFree { pkey: c_int },

    #[syscall(statx)]
    Statx {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        flags: c_uint,
        mask: c_uint,
        #[syscall(ptr())]
        buffer: statx,
    },

    #[syscall(io_pgetevents)]
    IoPgetevents {
        ctx_id: aio_context,
        min_nr: c_long,
        nr: c_long,
        #[syscall(ptr(count = nr))]
        events: io_event,
        #[syscall(ptr())]
        timeout: __kernel_timespec,
        #[syscall(ptr())]
        usig: aio_sigset,
    },

    #[syscall(rseq)]
    Rseq {
        #[syscall(private)]
        rseq: Opaque,
        #[syscall(private)]
        rseq_len: u32,
        flags: c_int,
        sig: u32,
    },

    // uretprobe should go here, but syscalls doesn't include it.
    #[syscall(pidfd_send_signal)]
    PidfdSendSignal {
        pidfd: Fd,
        sig: c_int,
        #[syscall(ptr())]
        info: siginfo_t,
        flags: c_uint,
    },

    #[syscall(io_uring_setup)]
    IoUringSetup {
        entries: u32,
        #[syscall(ptr())]
        params: io_uring_params,
    },

    #[syscall(io_uring_enter)]
    IoUringEnter {
        fd: Fd,
        to_submit: u32,
        min_complete: u32,
        flags: u32,
        #[syscall(ptr(opaque))]
        argp: Opaque,
        argsz: usize,
    },

    #[syscall(io_uring_register)]
    IoUringRegister {
        fd: Fd,
        opcode: c_uint,
        #[syscall(ptr(opaque))]
        arg: Opaque,
        nr_args: usize,
    },

    #[syscall(open_tree)]
    OpenTree {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        flags: c_uint,
    },

    #[syscall(move_mount)]
    MoveMount {
        from_dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        from_pathname: PathBuf,
        to_dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        to_pathname: PathBuf,
        flags: c_uint,
    },

    #[syscall(fsopen)]
    Fsopen {
        #[syscall(ptr(nul_terminated))]
        _fs_name: PathBuf,
        flags: c_uint,
    },

    #[syscall(fsconfig)]
    Fsconfig {
        fd: Fd,
        cmd: c_uint,
        #[syscall(ptr(nul_terminated))]
        _key: OsString,
        #[syscall(ptr(opaque))]
        _value: Opaque,
        aux: c_int,
    },

    #[syscall(fsmount)]
    Fsmount {
        fs_fd: Fd,
        flags: c_uint,
        attr_flags: c_uint,
    },

    #[syscall(fspick)]
    Fspick {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        path: PathBuf,
        flags: c_uint,
    },

    #[syscall(pidfd_open)]
    PidfdOpen { pid: Pid, flags: c_uint },

    #[syscall(clone3)]
    Clone3 {
        #[syscall(ptr())]
        uargs: clone_args,
        size: usize,
    },

    #[syscall(close_range)]
    CloseRange { fd: Fd, max_fd: Fd, flags: c_uint },

    #[syscall(openat2)]
    Openat2 {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        #[syscall(ptr())]
        how: open_how,
        usize: usize,
    },

    #[syscall(pidfd_getfd)]
    PidfdGetfd { pidfd: Fd, fd: Fd, flags: c_uint },

    #[syscall(faccessat2)]
    Faccessat2 {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        mode: c_int,
        flags: c_int,
    },

    #[syscall(process_madvise)]
    ProcessMadvise {
        pidfd: Fd,
        #[syscall(ptr(count = vlen))]
        vec: iovec,
        #[syscall(private)]
        vlen: usize,
        behavior: c_int,
        flags: c_uint,
    },

    #[syscall(epoll_pwait2)]
    EpollPwait2 {
        epfd: Fd,
        #[syscall(ptr(count = maxevents))]
        events: epoll_event,
        #[syscall(private)]
        maxevents: c_int,
        #[syscall(ptr())]
        timeout: __kernel_timespec,
        #[syscall(ptr())]
        sigmask: sigset_t,
        sigsetsize: usize,
    },

    #[syscall(mount_setattr)]
    MountSetattr {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        path: PathBuf,
        flags: c_uint,
        #[syscall(ptr())]
        uattr: mount_attr,
        usize: usize,
    },

    #[syscall(quotactl_fd)]
    QuotactlFd {
        fd: Fd,
        cmd: c_uint,
        id: __kernel_uid32_t,
        #[syscall(ptr(opaque))]
        addr: Opaque,
    },

    #[syscall(landlock_create_ruleset)]
    LandlockCreateRuleset {
        #[syscall(ptr())]
        attr: landlock_ruleset_attr,
        size: usize,
        flags: u32,
    },

    #[syscall(landlock_add_rule)]
    LandlockAddRule {
        ruleset_fd: Fd,
        #[syscall(private)]
        rule_type: u32,
        #[syscall(ptr(opaque))]
        rule_attr: Opaque,
        flags: u32,
    },

    #[syscall(landlock_restrict_self)]
    LandlockRestrictSelf { ruleset_fd: Fd, flags: u32 },

    #[syscall(memfd_secret)]
    MemfdSecret { flags: c_uint },

    #[syscall(process_mrelease)]
    ProcessMrelease { pidfd: Fd, flags: c_uint },

    #[syscall(futex_waitv)]
    FutexWaitv {
        #[syscall(ptr(count = nr_futexes))]
        waiters: futex_waitv,
        #[syscall(private)]
        nr_futexes: c_uint,
        flags: c_uint,
        #[syscall(ptr())]
        timeout: __kernel_timespec,
        clockid: __kernel_clockid_t,
    },

    #[syscall(set_mempolicy_home_node)]
    SetMempolicyHomeNode {
        #[syscall(ptr(opaque))]
        start: Opaque,
        len: c_ulong,
        home_node: c_ulong,
        flags: c_ulong,
    },

    #[syscall(cachestat)]
    Cachestat {
        fd: Fd,
        #[syscall(ptr())]
        cstat_range: cachestat_range,
        #[syscall(ptr())]
        cstat: cachestat,
        flags: c_uint,
    },

    #[syscall(fchmodat2)]
    Fchmodat2 {
        dfd: Fd,
        #[syscall(ptr(nul_terminated))]
        filename: PathBuf,
        mode: c_ushort,
        flags: c_uint,
    },

    #[syscall(map_shadow_stack)]
    MapShadowStack {
        #[syscall(ptr(opaque))]
        addr: Opaque,
        size: c_ulong,
        flags: c_uint,
    },

    #[syscall(futex_wake)]
    FutexWake {
        #[syscall(ptr(opaque))]
        uaddr: Opaque,
        mask: c_ulong,
        nr: c_int,
        flags: c_uint,
    },

    #[syscall(futex_wait)]
    FutexWait {
        #[syscall(ptr(opaque))]
        uaddr: Opaque,
        val: c_ulong,
        mask: c_ulong,
        flags: c_uint,
        #[syscall(ptr())]
        timeout: __kernel_timespec,
        clockid: __kernel_clockid_t,
    },

    #[syscall(futex_requeue)]
    FutexRequeue {
        #[syscall(ptr())]
        waiters: futex_waitv,
        flags: c_uint,
        nr_wake: c_int,
        nr_requeue: c_int,
    },

    #[syscall(statmount)]
    Statmount {
        #[syscall(ptr())]
        req: mnt_id_req,
        #[syscall(ptr(count = nr_mnt_ids))]
        mnt_ids: u64,
        #[syscall(private)]
        nr_mnt_ids: usize,
        flags: c_uint,
    },

    #[syscall(listmount)]
    Listmount {
        #[syscall(ptr())]
        req: mnt_id_req,
        #[syscall(ptr(count = nr_mnt_ids))]
        mnt_ids: u64,
        #[syscall(private)]
        nr_mnt_ids: usize,
        flags: c_uint,
    },
    // As of Linux 6.14, there are a handful more syscalls, but none of the underlying crates
    // really support them. So for now we'll let them bucket into the fallback Other variant and we
    // can add them later if necessary.
}

impl Getsockopt {
    /// # Safety
    ///
    /// This can only be called at syscall exit.
    pub unsafe fn optval(&self, pid: Pid) -> core::Result<Box<[u8]>> {
        unsafe {
            let optlen: c_int = core::read_to_type(pid, self.optlen)?;
            core::read(pid, self.optval, optlen as usize)
        }
    }
}

impl Sendto {
    /// # Safety
    ///
    /// This can only be called on syscall entry.
    pub unsafe fn addr(&self, pid: Pid) -> core::Result<Option<SockaddrStorage>> {
        if self.addr.is_null() {
            Ok(None)
        } else {
            let raw = unsafe { core::read(pid, self.addr, self.addr_len as usize) }?;
            unsafe {
                SockaddrStorage::from_raw(
                    raw.as_ptr() as *const nix::libc::sockaddr,
                    Some(raw.len() as socklen_t),
                )
            }
            .map(Some)
            .ok_or(core::Error::SockaddrParse {
                addr: self.addr,
                pid,
            })
        }
    }
}

impl Recvfrom {
    /// # Safety
    ///
    /// This can only be called on syscall exit, only if the protocol provides source addresses,
    /// and only on success.
    pub unsafe fn addr(&self, pid: Pid) -> core::Result<Option<SockaddrStorage>> {
        if self.addr.is_null() {
            Ok(None)
        } else {
            let raw = unsafe { core::read(pid, self.addr, self.addr_len as usize) }?;
            unsafe {
                SockaddrStorage::from_raw(
                    raw.as_ptr() as *const nix::libc::sockaddr,
                    Some(raw.len() as socklen_t),
                )
            }
            .map(Some)
            .ok_or(core::Error::SockaddrParse {
                addr: self.addr,
                pid,
            })
        }
    }
}

impl Sendmsg {
    /// # Safety
    ///
    /// This can only be called on syscall entry.
    pub unsafe fn msg(&self, pid: Pid) -> core::Result<Msghdr> {
        unsafe { core::read_to_type::<libc::msghdr>(pid, self.msg) }.map(Into::into)
    }
}

impl Recvmsg {
    /// # Safety
    ///
    /// This can only be called on syscall exit, and only on success.
    pub unsafe fn msg(&self, pid: Pid) -> core::Result<Msghdr> {
        unsafe { core::read_to_type::<libc::msghdr>(pid, self.msg) }.map(Into::into)
    }
}

impl Execve {
    /// # Safety
    ///
    /// This can only be called on syscall entry.
    pub unsafe fn argv(&self, pid: Pid) -> impl Iterator<Item = core::Result<OsString>> {
        NulTerminatedCharPtrArrayIterator {
            pid,
            n: 0,
            base: self.argv,
        }
    }

    /// # Safety
    ///
    /// This can only be called on syscall entry.
    pub unsafe fn envp(&self, pid: Pid) -> impl Iterator<Item = core::Result<OsString>> {
        NulTerminatedCharPtrArrayIterator {
            pid,
            n: 0,
            base: self.envp,
        }
    }
}

impl Execveat {
    /// # Safety
    ///
    /// This can only be called on syscall entry.
    pub unsafe fn argv(&self, pid: Pid) -> impl Iterator<Item = core::Result<OsString>> {
        NulTerminatedCharPtrArrayIterator {
            pid,
            n: 0,
            base: self.argv,
        }
    }

    /// # Safety
    ///
    /// This can only be called on syscall entry.
    pub unsafe fn envp(&self, pid: Pid) -> impl Iterator<Item = core::Result<OsString>> {
        NulTerminatedCharPtrArrayIterator {
            pid,
            n: 0,
            base: self.envp,
        }
    }
}

impl IoSubmit {
    /// # Safety
    ///
    /// This can only be called on syscall entry.
    pub unsafe fn iocbpp(&self, pid: Pid) -> impl Iterator<Item = core::Result<iocb>> {
        // There's an extra layer of indirection here, so we have to read twice, annoyingly.
        (0..(self.nr as usize)).map(move |i| unsafe {
            let addr = Opaque(core::read_to_type(
                pid,
                self.iocbpp.at(i, size_of::<usize>()),
            )?);
            core::read_to_type(pid, addr)
        })
    }
}

impl GetRobustList {
    /// # Safety
    ///
    /// This can only be called on syscall exit, and only on success.
    pub unsafe fn head(&self, pid: Pid) -> core::Result<robust_list_head> {
        unsafe {
            let head_ptr = Opaque(core::read_to_type(pid, self.head_ptr)?);
            core::read_to_type(pid, head_ptr)
        }
    }
}

impl Pipe2 {
    /// # Safety
    ///
    /// This can only be called on syscall entry.
    pub unsafe fn fildes(&self, pid: Pid) -> core::Result<[Fd; 2]> {
        unsafe {
            let a = core::read_to_type(pid, self.fildes)?;
            let b = core::read_to_type(pid, self.fildes.at(1, size_of::<Fd>()))?;

            Ok([a, b])
        }
    }
}

impl NameToHandleAt {
    /// # Safety
    ///
    /// This can only be called on syscall exit, and only on success.
    pub unsafe fn handle(&self, pid: Pid) -> core::Result<file_handle> {
        unsafe { file_handle::from_raw(pid, self.handle) }
    }
}

impl OpenByHandleAt {
    /// # Safety
    ///
    /// This can only be called on syscall entry.
    pub unsafe fn handle(&self, pid: Pid) -> core::Result<file_handle> {
        unsafe { file_handle::from_raw(pid, self.handle) }
    }
}

impl Rseq {
    /// # Safety
    ///
    /// This can only be called on syscall entry.
    pub unsafe fn rseq(&self, pid: Pid) -> core::Result<rseq> {
        unsafe { rseq::from_raw(pid, self.rseq, self.rseq_len as usize) }
    }
}

impl LandlockAddRule {
    pub fn rule_type(&self) -> landlock_rule_type {
        unsafe { std::mem::transmute(self.rule_type) }
    }
}

#[derive(Debug)]
struct NulTerminatedCharPtrArrayIterator {
    pid: Pid,
    n: usize,
    base: Opaque,
}

impl NulTerminatedCharPtrArrayIterator {
    unsafe fn next_impl(&mut self) -> core::Result<Option<OsString>> {
        eprintln!("n = {}", self.n);
        let mut ptr = Opaque(unsafe {
            core::read_to_type(self.pid, self.base.at(self.n, size_of::<usize>()))
        }?);
        eprintln!("argv[{}] = {ptr:?}", self.n);

        unsafe {
            use nix::{
                errno::Errno,
                libc::{self, PTRACE_PEEKDATA},
            };

            let addr = self.base.at(self.n, size_of::<usize>()).0;

            Errno::clear();
            let word = libc::ptrace(PTRACE_PEEKDATA, self.pid, addr, 0);
            if word == -1 {
                let e = Errno::last();
                if (e as i32) != 0 {
                    return Err(core::Error::Read {
                        e,
                        pid: self.pid,
                        addr: Opaque(addr),
                    });
                }
            }

            eprintln!("raw word: 0x{:016x}", word as u64);
            ptr = Opaque(word as usize);
        }

        self.n += 1;
        Ok(if ptr.is_null() {
            None
        } else {
            Some(OsString::from_vec(unsafe {
                core::read_to_nul(self.pid, ptr)
            }?))
        })
    }
}

impl Iterator for NulTerminatedCharPtrArrayIterator {
    type Item = core::Result<OsString>;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe { self.next_impl() }.transpose()
    }
}

#[allow(non_camel_case_types)]
pub type aio_context = c_ulong;

#[allow(non_camel_case_types)]
pub type mqd_t = c_long;

/// Wrapper for the Linux kernel's (long deprecated) `ustat` struct.
#[allow(non_camel_case_types)]
#[derive(Debug)]
#[repr(C)]
pub struct ustat {
    pub f_tfree: __kernel_daddr_t,
    // XXX: if Rust gets support for the DEC Alpha, this should also get the same cfg handling as
    // s390x, since both use 32 bit inode types.
    #[cfg(target_arch = "s390x")]
    pub f_tinode: c_uint,
    #[cfg(not(target_arch = "s390x"))]
    pub f_tinode: c_ulong,
    pub f_fname: [i8; 6],
    pub f_fpack: [i8; 6],
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
#[repr(C)]
pub struct kexec_segment {
    buf: *mut c_void,
    bufsz: usize,
    mem: *mut c_void,
    memsz: usize,
}

impl kexec_segment {
    /// # Safety
    ///
    /// The `buf` and `bufsz` syscall arguments must be valid.
    pub unsafe fn buf(&self, pid: Pid) -> core::Result<Box<[u8]>> {
        unsafe { core::read(pid, Opaque(self.buf.addr()), self.bufsz) }
    }

    /// # Safety
    ///
    /// The `mem` and `memsz` syscall arguments must be valid.
    pub unsafe fn mem(&self, pid: Pid) -> core::Result<Box<[u8]>> {
        unsafe { core::read(pid, Opaque(self.mem.addr()), self.memsz) }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub struct file_handle {
    pub handle_type: c_int,
    pub f_handle: Box<[u8]>,
}

impl file_handle {
    unsafe fn from_raw(pid: Pid, addr: Opaque) -> core::Result<Self> {
        #[repr(C)]
        struct Raw {
            handle_bytes: c_uint,
            handle_type: c_int,
            f_handle: [c_char; 0],
        }

        unsafe {
            let raw: Raw = core::read_to_type(pid, addr)?;
            Ok(Self {
                handle_type: raw.handle_type,
                f_handle: core::read(
                    pid,
                    addr.with_offset(offset_of!(Raw, f_handle)),
                    raw.handle_bytes as usize,
                )?,
            })
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
#[repr(C)]
pub struct aio_sigset {
    sigmask: usize,
    sigsetsize: usize,
}

impl aio_sigset {
    /// # Safety
    ///
    /// The `sigmask` pointer must be valid.
    pub unsafe fn sigmask(&self, pid: Pid) -> core::Result<sigset_t> {
        unsafe { core::read_to_type(pid, Opaque(self.sigmask)) }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub struct rseq {
    pub cpu_id_start: u32,
    pub cpu_id: u32,
    pub rseq_cs: u64,
    pub flags: u32,
    pub node_id: u32,
    pub mm_cid: u32,
    pub end: Vec<u8>,
}

impl rseq {
    unsafe fn from_raw(pid: Pid, addr: Opaque, len: usize) -> core::Result<Self> {
        #[repr(C)]
        struct Raw {
            cpu_id_start: u32,
            cpu_id: u32,
            rseq_cs: u64,
            flags: u32,
            node_id: u32,
            mm_cid: u32,
            end: [c_char; 0],
        }

        unsafe {
            let mut bytes = core::read(pid, addr, len)?.into_vec();
            let raw: Raw = std::mem::transmute_copy(&bytes.as_slice());

            Ok(Self {
                cpu_id_start: raw.cpu_id_start,
                cpu_id: raw.cpu_id,
                rseq_cs: raw.rseq_cs,
                flags: raw.flags,
                node_id: raw.node_id,
                mm_cid: raw.mm_cid,
                end: bytes.split_off(offset_of!(Raw, end)),
            })
        }
    }
}
