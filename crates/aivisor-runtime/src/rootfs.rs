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

    /// Chown `upper` and `work`, and everything already inside them, to
    /// the sandbox's own uid/gid, so that the child — which, after
    /// `caps::become_namespace_root`, holds a credential resolving to
    /// exactly this host uid/gid — can access and create files there.
    /// Must run in the PARENT (real root: `chown(2)` to an arbitrary host
    /// uid is only unambiguous from outside any user namespace — see
    /// `caps::become_namespace_root`'s doc comment for why the child's own
    /// credential can't be used for this), before `mount_overlay()`.
    ///
    /// Recursive, not just the two top-level directories: callers are
    /// documented to stage content into `upper` (via
    /// `SandboxManager::workspace_upper_dir`) BEFORE the sandbox process —
    /// and therefore its uid_base — exists, so that staged content is
    /// necessarily created by the real-root daemon, not this sandbox's
    /// uid. A non-recursive chown left it owned by real root, invisible-
    /// enough to the child that even `mkdir` on an already-existing
    /// directory the merge inherited from `upper` (not a copy-up, just an
    /// existing entry) failed closed with EACCES instead of the ordinary
    /// EEXIST every other pre-existing directory hit — verified
    /// empirically on a real kernel (Ubuntu 24.04, 6.8.0).
    pub fn chown_upper_and_work(&self, uid: u32, gid: u32) -> Result<(), Error> {
        chown_recursive(&self.upper, uid, gid)?;
        chown_recursive(&self.work, uid, gid)?;
        Ok(())
    }

    /// Mount the overlay filesystem. Must be called in the CHILD, inside
    /// its own `CLONE_NEWUSER`/`CLONE_NEWNS` namespaces, AFTER
    /// `caps::become_namespace_root` and the `/`-remount-private step, and
    /// before `pivot_root`. Two real-kernel constraints (Ubuntu 24.04,
    /// 6.8.0) shaped this ordering, both empirically verified, not
    /// assumed: (1) mounting before `become_namespace_root` fails closed —
    /// this process's credential still predates the uid_map at that point
    /// and can't be stamped onto anything it creates or copies up; (2)
    /// mounting this in the PARENT instead (before `clone3()`, so the
    /// child would inherit it already-mounted) was tried and reverted —
    /// `pivot_root` refuses a mount created outside the CURRENT task's own
    /// user namespace ("locked", in kernel terms) regardless of
    /// propagation settings, even though the child does inherit an
    /// independent copy of the mount itself via `CLONE_NEWNS`.
    /// `lower`/`upper`/`work` MUST be three distinct directories — nesting
    /// `upper` inside `lower` (or mounting the overlay onto `lower` itself)
    /// is rejected by the kernel with EINVAL, and is exactly the mistake
    /// this function exists to make impossible to repeat at the call site.
    pub fn mount_overlay(&self) -> Result<(), Error> {
        // xino=off: upper/work live under /run (tmpfs, `inode64`), whose
        // inode numbers are large enough that overlayfs's default xino
        // inode-bit-stealing (encoding a layer index into the high bits of
        // st_ino, "auto"-enabled whenever the layers can support it) has no
        // headroom left to steal — verified on a real kernel (Ubuntu
        // 24.04, 6.8.0): file creation in the merged tree then fails with
        // EOVERFLOW (dmesg: "overlayfs: "xino" feature enabled using 2
        // upper inode bits"). This codebase never exports the sandbox
        // rootfs over NFS, the only reason xino's cross-layer-unique inode
        // numbers would matter, so disabling it is correct, not a
        // workaround with a downside.
        let data = format!(
            "lowerdir={},upperdir={},workdir={},xino=off",
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

/// `lchown`, not `chown`: staged content under `upper` may include a
/// symlink, and `chown`'s follow-the-target behavior on one pointing
/// outside the sandbox's own tree would silently chown an unrelated host
/// path instead of the symlink itself. Recursion uses `DirEntry::file_type`
/// (`lstat`-based, doesn't follow symlinks) rather than `Path::is_dir`
/// (which does) for the same reason, and to avoid an infinite loop on a
/// symlink cycle.
fn chown_recursive(path: &Path, uid: u32, gid: u32) -> Result<(), Error> {
    let path_c = path_cstring(path)?;
    let ret = unsafe { libc::lchown(path_c.as_ptr(), uid, gid) };
    if ret != 0 {
        return Err(Error::MountSetup(format!(
            "lchown {} to {uid}:{gid}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }

    let file_type = fs::symlink_metadata(path)
        .map_err(|e| Error::MountSetup(format!("symlink_metadata {}: {e}", path.display())))?
        .file_type();
    if file_type.is_dir() {
        let entries = fs::read_dir(path)
            .map_err(|e| Error::MountSetup(format!("read_dir {}: {e}", path.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| Error::MountSetup(format!("read_dir entry: {e}")))?;
            chown_recursive(&entry.path(), uid, gid)?;
        }
    }

    Ok(())
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
