#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use escargot::{
    CargoBuild,
    format::{Artifact, Message},
};
use ptrace_iterator::{CommandTrace, Syscall, Tracer, core::Fd, event::Event};
use tempfile::TempDir;

#[test]
fn test_read_file() -> anyhow::Result<()> {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/read_file/Cargo.toml");
    let binary = Binary::build(manifest_path, "read_file")?;

    // Run our own version of `cat` that we know will open the given file with openat, read from it,
    // and close it.
    let mut cmd = Command::new(binary.path());
    let child = cmd
        .traceme()
        .arg("/proc/cpuinfo")
        .stdout(Stdio::null())
        .spawn()?;

    bitflags::bitflags! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        struct Seen: u8 {
            const OPEN = 0b0000001;
            const READ = 0b0000010;
            const CLOSE = 0b00000100;
        }
    }

    // Now we want to actually observe those syscalls.
    let mut last = None;
    let mut stdin_fd = None;
    let mut seen = Seen::empty();
    let mut tracer = Tracer::<String>::new(child)?;
    for result in tracer.iter() {
        match result? {
            Event::SyscallEntry(ref mut event) => match event.syscall() {
                Syscall::Openat(args)
                    if args.dfd().is_at_working_directory()
                        && unsafe { args.filename(event.pid()) }?.as_path() == "/proc/cpuinfo" =>
                {
                    last = Some(Seen::OPEN);

                    // Stash some userdata.
                    event.set_userdata(String::from("userdata"));
                }
                Syscall::Read(args) if stdin_fd.is_some_and(|fd| fd == args.fd()) => {
                    last = Some(Seen::READ);
                }
                Syscall::Close(args) if stdin_fd.is_some_and(|fd| fd == args.fd()) => {
                    last = Some(Seen::CLOSE);
                }
                _ => {
                    last = None;
                }
            },
            Event::SyscallExit(ref mut event) => {
                match event.syscall() {
                    Some(Syscall::Openat(_)) if last == Some(Seen::OPEN) && !event.is_error() => {
                        stdin_fd = Some(Fd::try_from(event.sval())?);
                        seen.insert(Seen::OPEN);

                        // Make sure the userdata stayed.
                        assert_eq!(event.userdata(), Some(&String::from("userdata")));
                        assert_eq!(event.take_userdata(), Some(String::from("userdata")));
                    }
                    Some(Syscall::Read(_)) if last == Some(Seen::READ) && !event.is_error() => {
                        seen.insert(Seen::READ);
                        assert!(event.userdata().is_none());
                    }
                    Some(Syscall::Close(_)) if last == Some(Seen::CLOSE) && !event.is_error() => {
                        seen.insert(Seen::CLOSE);
                        assert!(event.userdata().is_none());
                    }
                    _ => {}
                }
                last = None;
            }
            _ => {}
        }
    }

    assert!(tracer.status().is_some_and(|status| status.success()));
    assert!(seen.is_all());

    Ok(())
}

struct Binary {
    path: PathBuf,
    #[expect(unused)]
    target: TempDir,
}

impl Binary {
    pub fn build(manifest_path: impl AsRef<Path>, binary: &str) -> anyhow::Result<Self> {
        let manifest_path = manifest_path.as_ref();
        let target = TempDir::new()?;

        fn message_executable(msg: escargot::Message) -> anyhow::Result<Option<PathBuf>> {
            Ok(match msg.decode()? {
                Message::CompilerArtifact(Artifact {
                    executable: Some(executable),
                    ..
                }) => Some(executable.to_path_buf()),
                _ => None,
            })
        }

        let path = CargoBuild::new()
            .bin(binary)
            .manifest_path(manifest_path)
            .target_dir(target.path())
            .exec()?
            .filter_map(|msg| match msg {
                Ok(msg) => match message_executable(msg) {
                    Ok(Some(result)) => Some(Ok(result)),
                    Ok(None) => None,
                    Err(e) => Some(Err(e)),
                },
                Err(e) => Some(Err(e.into())),
            })
            .next()
            .ok_or_else(|| anyhow::anyhow!("no binary built from {}", manifest_path.display()))??;

        Ok(Self { path, target })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
