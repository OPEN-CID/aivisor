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
                    e.ok().map_or(false, |e| {
                        let path = e.path().join("cgroup.kill");
                        path.exists()
                    })
                })
            })
            .unwrap_or(false)
}

fn probe_overlayfs() -> bool {
    Path::new("/sys/module/overlay").exists()
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
