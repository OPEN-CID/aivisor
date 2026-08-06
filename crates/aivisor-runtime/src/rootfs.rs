use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};

use aivisor_core::{Error, WorkspaceSpec};

use crate::abi;

/// An overlay rootfs: `lower` (read-only template/base image) + `upper`
/// (writable, tmpfs or a per-sandbox dir) + `work` (overlayfs scratch,
/// same filesystem as `upper`) => `merged` (the mount target actually
/// pivoted into).
#[derive(Clone)]
pub struct Rootfs {
    pub lower: PathBuf,
    pub merged: PathBuf,
    pub upper: PathBuf,
    pub work: PathBuf,
}

impl Rootfs {
    pub fn prepare(
        template_dir: &Path,
        _spec: &WorkspaceSpec,
        sandbox_id: &str,
    ) -> Result<Self, Error> {
        let base_dir = PathBuf::from(format!("/run/aivisor/sandboxes/{sandbox_id}"));
        fs::create_dir_all(&base_dir)
            .map_err(|e| Error::MountSetup(format!("create sandbox dir: {e}")))?;

        let upper = base_dir.join("upper");
        let work = base_dir.join("work");
        let merged = base_dir.join("merged");

        fs::create_dir(&upper).map_err(|e| Error::MountSetup(format!("create upper: {e}")))?;
        fs::create_dir(&work).map_err(|e| Error::MountSetup(format!("create work: {e}")))?;
        fs::create_dir(&merged).map_err(|e| Error::MountSetup(format!("create merged: {e}")))?;

        Ok(Self {
            lower: template_dir.to_path_buf(),
            merged,
            upper,
            work,
        })
    }

    /// Mount the overlay filesystem. Must be called inside the child mount
    /// namespace after the `/`-remount-private step and before pivot_root.
    /// `lower`/`upper`/`work` MUST be three distinct directories — nesting
    /// `upper` inside `lower` (or mounting the overlay onto `lower` itself)
    /// is rejected by the kernel with EINVAL, and is exactly the mistake
    /// this function exists to make impossible to repeat at the call site.
    pub fn mount_overlay(&self) -> Result<(), Error> {
        let data = format!(
            "lowerdir={},upperdir={},workdir={}",
            self.lower.display(),
            self.upper.display(),
            self.work.display()
        );

        let overlay_src = CString::new("overlay").map_err(cstring_err)?;
        let overlay_fstype = CString::new("overlay").map_err(cstring_err)?;
        let merged_c = path_cstring(&self.merged)?;
        let data_c = CString::new(data).map_err(cstring_err)?;

        let ret = unsafe {
            abi::mount(
                overlay_src.as_ptr(),
                merged_c.as_ptr(),
                overlay_fstype.as_ptr(),
                (libc::MS_NODEV | libc::MS_NOSUID) as libc::c_ulong,
                data_c.as_ptr() as *const libc::c_void,
            )
        };

        if ret != 0 {
            return Err(Error::MountSetup(format!(
                "overlay mount ({} on {}) failed: {}",
                self.lower.display(),
                self.merged.display(),
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    pub fn workspace_archive(&self) -> Result<Vec<u8>, Error> {
        Err(Error::Unsupported("workspace archive in Phase 4".into()))
    }
}

fn cstring_err(e: std::ffi::NulError) -> Error {
    Error::MountSetup(format!("interior NUL in mount argument: {e}"))
}

pub(crate) fn path_cstring(p: &Path) -> Result<CString, Error> {
    CString::new(p.as_os_str().as_encoded_bytes())
        .map_err(|e| Error::MountSetup(format!("interior NUL in path {}: {e}", p.display())))
}

// Rootfs::prepare creates its sandbox dir under the real /run/aivisor,
// which requires root — same reason manager.rs's create/destroy tests are
// gated the same way. The whole module is gated, not just the test fn,
// since `use super::*` would otherwise be unused with the feature off.
#[cfg(all(test, feature = "privileged-tests"))]
mod tests {
    use super::*;

    #[test]
    fn test_rootfs_prepare_paths() {
        // Unique per run (PID + UUID, not a fixed literal): a fixed sandbox
        // id would make `Rootfs::prepare`'s `create_dir` (non-recursive,
        // EEXIST on a repeat) fail on any second run within the same boot,
        // since /run/aivisor/sandboxes/<id> is never otherwise cleaned up
        // between separate test invocations.
        let sandbox_id = format!("test-{}-{}", std::process::id(), uuid::Uuid::now_v7());
        let tmp = std::env::temp_dir().join(format!("aivisor-rootfs-test-{sandbox_id}"));
        let _ = fs::create_dir_all(&tmp);

        let spec = WorkspaceSpec::Tmpfs { size: 1073741824 };
        let rootfs = Rootfs::prepare(&tmp, &spec, &sandbox_id).unwrap();
        assert!(rootfs.merged.exists());
        assert!(rootfs.upper.exists());
        assert!(rootfs.work.exists());
        assert_eq!(rootfs.lower, tmp);
        // lower/upper/work must never collapse onto each other — that's
        // the exact bug (nested/aliased overlay dirs) this type prevents.
        assert_ne!(rootfs.lower, rootfs.upper);
        assert_ne!(rootfs.upper, rootfs.work);
        assert_ne!(rootfs.lower, rootfs.merged);

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(format!("/run/aivisor/sandboxes/{sandbox_id}"));
    }
}
