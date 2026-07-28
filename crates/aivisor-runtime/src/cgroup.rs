use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use aivisor_core::{CgroupId, Error, ResourceLimits, SandboxId};
use rustix::fs::{Mode, OFlags, Stat};

pub struct Cgroup {
    pub path: PathBuf,
    pub fd: OwnedFd,
    pub id: CgroupId,
}

impl Cgroup {
    pub fn create(root: &Path, id: &SandboxId) -> Result<Self, Error> {
        let cgroup_root = root.join("aivisor");
        let cgroup_path = cgroup_root.join(id.to_string());

        fs::create_dir_all(&cgroup_root).map_err(|e| {
            Error::CgroupSetup(format!("failed to create aivisor cgroup root: {e}"))
        })?;

        delegate_controllers(&cgroup_root)?;

        fs::create_dir(&cgroup_path)
            .map_err(|e| Error::CgroupSetup(format!("failed to create sandbox cgroup: {e}")))?;

        let fd = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&cgroup_path)
            .map_err(|e| Error::CgroupSetup(format!("failed to open cgroup dir fd: {e}")))?;
        let fd = OwnedFd::from(fd);

        let cgid = Self::read_cgroup_id(&cgroup_path)?;

        Ok(Self {
            path: cgroup_path,
            fd,
            id: CgroupId(cgid),
        })
    }

    pub fn apply(&self, limits: &ResourceLimits) -> Result<(), Error> {
        if let Some(ref cpu) = limits.cpu_max {
            let val = format!("{} {}", cpu.quota_us, cpu.period_us);
            write_file(&self.path.join("cpu.max"), &val)?;
        }

        if let Some(high) = limits.memory_high {
            write_file(&self.path.join("memory.high"), &high.to_string())?;
        } else if let Some(max) = limits.memory_max {
            let high = max.saturating_mul(9) / 10;
            write_file(&self.path.join("memory.high"), &high.to_string())?;
        }

        if let Some(max) = limits.memory_max {
            write_file(&self.path.join("memory.max"), &max.to_string())?;
        }

        if let Some(pids) = limits.pids_max {
            write_file(&self.path.join("pids.max"), &pids.to_string())?;
        }

        if let Some(swap) = limits.swap_max {
            write_file(&self.path.join("memory.swap.max"), &swap.to_string())?;
        }

        for io in &limits.io_max {
            let val = format!(
                "{}:{} rbps={} wbps={}",
                io.major, io.minor, io.rbps, io.wbps
            );
            write_file(&self.path.join("io.max"), &val)?;
        }

        Ok(())
    }

    pub fn freeze(&self) -> Result<(), Error> {
        write_file(&self.path.join("cgroup.freeze"), "1")
            .map_err(|e| Error::CgroupSetup(format!("freeze failed: {e}")))
    }

    pub fn thaw(&self) -> Result<(), Error> {
        write_file(&self.path.join("cgroup.freeze"), "0")
            .map_err(|e| Error::CgroupSetup(format!("thaw failed: {e}")))
    }

    pub fn kill_all(&self) -> Result<(), Error> {
        let kill_path = self.path.join("cgroup.kill");
        if kill_path.exists() {
            write_file(&kill_path, "1")
                .map_err(|e| Error::CgroupSetup(format!("cgroup.kill failed: {e}")))?;
        } else {
            let procs = fs::read_to_string(self.path.join("cgroup.procs"))
                .map_err(|e| Error::CgroupSetup(format!("read cgroup.procs failed: {e}")))?;
            for line in procs.lines() {
                let pid: i32 = line
                    .trim()
                    .parse()
                    .map_err(|_| Error::CgroupSetup("invalid pid in cgroup.procs".into()))?;
                if pid > 0 {
                    let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
                }
            }
        }
        Ok(())
    }

    pub fn stats(&self) -> Result<CgroupStats, Error> {
        let memory_current = read_u64(&self.path.join("memory.current")).ok();
        let pids_current = read_u64(&self.path.join("pids.current")).ok();
        let cpu_stat = fs::read_to_string(self.path.join("cpu.stat")).ok();

        Ok(CgroupStats {
            memory_current,
            pids_current,
            cpu_stat,
        })
    }

    pub fn pressure(&self) -> Result<Psi, Error> {
        let cpu_pressure = read_pressure(&self.path.join("cpu.pressure")).ok();
        let memory_pressure = read_pressure(&self.path.join("memory.pressure")).ok();
        Ok(Psi {
            cpu_pressure,
            memory_pressure,
        })
    }

    pub fn events(&self) -> Result<EventStream, Error> {
        let content = fs::read_to_string(self.path.join("memory.events"))
            .map_err(|e| Error::CgroupSetup(format!("read memory.events: {e}")))?;
        let mut oom_kill = false;
        for line in content.lines() {
            if line.starts_with("oom_kill") {
                let val: u64 = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                oom_kill = val > 0;
            }
        }
        Ok(EventStream { oom_kill })
    }

    pub fn destroy(self) -> Result<(), Error> {
        self.kill_all()?;

        let populated_path = self.path.join("cgroup.events");
        wait_for_empty(&populated_path, Duration::from_secs(2))?;

        drop(self.fd);

        fs::remove_dir(&self.path).map_err(|e| Error::CgroupSetup(format!("rmdir cgroup: {e}")))?;

        Ok(())
    }

    fn read_cgroup_id(path: &Path) -> Result<u64, Error> {
        use rustix::fs::stat;
        let stat = stat(path).map_err(|e| Error::CgroupSetup(format!("stat cgroup dir: {e}")))?;
        Ok(stat.st_ino as u64)
    }
}

#[derive(Debug)]
pub struct CgroupStats {
    pub memory_current: Option<u64>,
    pub pids_current: Option<u64>,
    pub cpu_stat: Option<String>,
}

#[derive(Debug)]
pub struct Psi {
    pub cpu_pressure: Option<String>,
    pub memory_pressure: Option<String>,
}

#[derive(Debug)]
pub struct EventStream {
    pub oom_kill: bool,
}

fn write_file(path: &Path, contents: &str) -> io::Result<()> {
    fs::write(path, contents)
}

fn read_u64(path: &Path) -> io::Result<u64> {
    let s = fs::read_to_string(path)?;
    s.trim()
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn read_pressure(path: &Path) -> io::Result<String> {
    fs::read_to_string(path)
}

fn delegate_controllers(cgroup_root: &Path) -> Result<(), Error> {
    let subtree_path = cgroup_root.join("cgroup.subtree_control");
    if !subtree_path.exists() {
        return Err(Error::CgroupSetup(
            "cgroup.subtree_control missing under aivisor cgroup root — cgroup v2 delegation not available".into(),
        ));
    }
    // +io is best-effort: some cgroup v2 hierarchies don't wire an io
    // controller in at all (no blkio/io accounting backend configured),
    // and io limits are the least safety-critical of the four (a missing
    // io.max cannot let a sandbox process escape or read/write outside its
    // confinement, only affect its own throughput). cpu/memory/pids are not
    // best-effort: those enforce the actual resource-exhaustion and
    // fork-bomb protections this sandbox depends on, so a failure to
    // delegate any of them must fail closed rather than silently produce
    // an unconfined sandbox.
    for ctrl in ["+cpu", "+memory", "+pids"] {
        fs::write(&subtree_path, ctrl).map_err(|e| {
            Error::CgroupSetup(format!("delegate controller {ctrl}: {e}"))
        })?;
    }
    let _ = fs::write(&subtree_path, "+io");
    Ok(())
}

fn wait_for_empty(populated_path: &Path, timeout: Duration) -> Result<(), Error> {
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > timeout {
            return Err(Error::CgroupSetup(
                "timeout waiting for cgroup to become empty".into(),
            ));
        }
        let content = fs::read_to_string(populated_path)
            .map_err(|e| Error::CgroupSetup(format!("read cgroup.events: {e}")))?;
        let populated = content
            .lines()
            .any(|l| l.starts_with("populated ") && l.ends_with("1"));
        if !populated {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn test_cgroup_id_from_stat() {
        let tmp = std::env::temp_dir().join(format!("aivisor-test-cg-{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp);
        let stat = rustix::fs::stat(&tmp).unwrap();
        let ino = stat.st_ino;
        assert!(ino > 0);
        let _ = fs::remove_dir(&tmp);
    }
}
