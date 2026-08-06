use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct KernelCaps {
    pub kernel: (u32, u32),
    pub cgroup_v2: bool,
    pub clone3: bool,
    pub clone_into_cgroup: bool,
    pub cgroup_kill: bool,
    pub overlayfs: bool,
    pub overlayfs_in_userns: bool,
    pub unprivileged_userns: bool,
    pub controllers: Vec<String>,
}

pub fn probe_all() -> KernelCaps {
    let kernel = probe_kernel_version();
    let cgroup_v2 = probe_cgroup_v2();
    let clone3 = probe_clone3();
    let clone_into_cgroup = probe_clone_into_cgroup();
    let cgroup_kill = probe_cgroup_kill();
    let overlayfs = probe_overlayfs();
    let overlayfs_in_userns = probe_overlayfs_in_userns();
    let unprivileged_userns = probe_unprivileged_userns();
    let controllers = probe_controllers();

    KernelCaps {
        kernel,
        cgroup_v2,
        clone3,
        clone_into_cgroup,
        cgroup_kill,
        overlayfs,
        overlayfs_in_userns,
        unprivileged_userns,
        controllers,
    }
}

fn probe_kernel_version() -> (u32, u32) {
    let info = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let parts: Vec<&str> = s.splitn(3, '.').collect();
            if parts.len() >= 2 {
                let major: u32 = parts[0].parse().unwrap_or(0);
                let minor: u32 = parts[1].parse().unwrap_or(0);
                Some((major, minor))
            } else {
                None
            }
        })
        .unwrap_or((0, 0));
    info
}

fn read_sysctl(name: &str) -> Option<String> {
    fs::read_to_string(format!("/proc/sys/{}", name.replace('.', "/")))
        .ok()
        .map(|s| s.trim().to_string())
}

fn probe_cgroup_v2() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

fn probe_clone3() -> bool {
    unsafe {
        let ret = libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0);
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            return err.raw_os_error() != Some(libc::ENOSYS);
        }
        true
    }
}

fn probe_clone_into_cgroup() -> bool {
    let ver = probe_kernel_version();
    ver.0 > 5 || (ver.0 == 5 && ver.1 >= 7)
}

fn probe_cgroup_kill() -> bool {
    Path::new("/sys/fs/cgroup").exists()
        && std::fs::read_dir("/sys/fs/cgroup")
            .map(|mut entries| {
                entries.any(|e| {
                    e.ok().is_some_and(|e| {
                        let path = e.path().join("cgroup.kill");
                        path.exists()
                    })
                })
            })
            .unwrap_or(false)
}

/// `/sys/module/overlay` only exists once something has already loaded the
/// module — on a fresh host where `CONFIG_OVERLAY_FS=m` (the common case;
/// see e.g. Ubuntu's generic kernel) and nothing has mounted an overlay yet,
/// that path is absent even though overlayfs is fully available and will
/// autoload on first use. A static path check therefore produces a false
/// negative for exactly the machine state a fresh install starts in.
/// Probing by a real, scratch-directory mount+unmount (matching how
/// `probe_clone3` already probes by attempting the real syscall, not by
/// inspecting a proxy for it) is the only way to know for certain.
fn probe_overlayfs() -> bool {
    // Keyed on PID *and* a fresh UUID: `cargo test` runs multiple tests as
    // threads inside one process, so PID alone is not unique enough to keep
    // two concurrent probe calls from colliding on the same mount point.
    let base = std::env::temp_dir().join(format!(
        "aivisor-probe-overlay-{}-{}",
        std::process::id(),
        uuid::Uuid::now_v7()
    ));
    let lower = base.join("lower");
    let upper = base.join("upper");
    let work = base.join("work");
    let merged = base.join("merged");

    let created = [&lower, &upper, &work, &merged]
        .iter()
        .all(|d| fs::create_dir_all(d).is_ok());
    if !created {
        let _ = fs::remove_dir_all(&base);
        return false;
    }

    let result = try_mount_overlay(&lower, &upper, &work, &merged);
    if result {
        unsafe {
            let merged_c = match std::ffi::CString::new(merged.to_string_lossy().as_bytes()) {
                Ok(c) => c,
                Err(_) => {
                    let _ = fs::remove_dir_all(&base);
                    return result;
                }
            };
            crate::abi::umount2(merged_c.as_ptr(), 0);
        }
    }
    let _ = fs::remove_dir_all(&base);
    result
}

fn try_mount_overlay(lower: &Path, upper: &Path, work: &Path, merged: &Path) -> bool {
    let Ok(overlay_src) = std::ffi::CString::new("overlay") else {
        return false;
    };
    let Ok(overlay_fstype) = std::ffi::CString::new("overlay") else {
        return false;
    };
    let Some(merged_str) = merged.to_str() else {
        return false;
    };
    let Ok(merged_c) = std::ffi::CString::new(merged_str) else {
        return false;
    };
    let data = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );
    let Ok(data_c) = std::ffi::CString::new(data) else {
        return false;
    };

    let ret = unsafe {
        crate::abi::mount(
            overlay_src.as_ptr(),
            merged_c.as_ptr(),
            overlay_fstype.as_ptr(),
            (libc::MS_NODEV | libc::MS_NOSUID) as libc::c_ulong,
            data_c.as_ptr() as *const libc::c_void,
        )
    };
    ret == 0
}

fn probe_overlayfs_in_userns() -> bool {
    let ver = probe_kernel_version();
    ver.0 > 5 || (ver.0 == 5 && ver.1 >= 11)
}

fn probe_unprivileged_userns() -> bool {
    read_sysctl("kernel.unprivileged_userns_clone")
        .map(|v| v == "1")
        .unwrap_or(true)
}

fn probe_controllers() -> Vec<String> {
    fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
        .ok()
        .map(|s| s.split_whitespace().map(|c| c.to_string()).collect())
        .unwrap_or_default()
}

pub fn check_hard_requirements(caps: &KernelCaps) -> Result<(), String> {
    if !caps.cgroup_v2 {
        return Err("cgroup v2 not detected. Boot with systemd.unified_cgroup_hierarchy=1".into());
    }
    if caps.controllers.is_empty() {
        return Err("No cgroup controllers found. Check /sys/fs/cgroup/cgroup.controllers".into());
    }
    if !caps.overlayfs {
        return Err("overlay filesystem not available. Ensure CONFIG_OVERLAY_FS=y".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_does_not_panic() {
        let caps = probe_all();
        eprintln!("kernel: {}.{}", caps.kernel.0, caps.kernel.1);
        eprintln!("cgroup_v2: {}", caps.cgroup_v2);
        eprintln!("overlayfs: {}", caps.overlayfs);
        eprintln!("controllers: {:?}", caps.controllers);
    }
}
