//! Adversarial smoke tests against a real, confined sandbox.
//!
//! The full categorized escape suite lives in `bench/escape` (its own
//! package, with a harness that stages and runs each scenario inside a
//! sandbox and fails the build on any ESCAPED/UNVERIFIED result — see that
//! package's README-equivalent doc comment in harness.rs). This file is a
//! smaller, self-contained complement: it doesn't need a second package or
//! a compiled scenario binary to stage, at the cost of covering fewer
//! scenarios.
//!
//! The previous version of this file shelled out to `sh -c "test_<name>"`
//! — shell functions that were never defined anywhere in the repo, so
//! every test here failed to even execute rather than testing confinement.
//!
//! Requires: `--features privileged-tests` on a Linux host with root/
//! capabilities, and a real base image at `/var/lib/aivisor/templates/base`
//! (images/base/build.sh is currently a stub — see that file's own TODO).
//! Until a real base image exists, these tests fail at `manager.create()`
//! or the `exec()` overlay mount, not because confinement is broken.
//!
//! Without the feature this file compiles to nothing — deliberately, rather
//! than to a test that prints "skipping" and reports green, which would make
//! an un-run gate look like a passing one in the CI summary.

#[cfg(feature = "privileged-tests")]
mod hostile_tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use aivisor_core::{ResourceLimits, SandboxId, SandboxSpec, WorkspaceSpec};
    use aivisor_runtime::manager::SandboxManager;

    fn new_sandbox(manager: &SandboxManager) -> SandboxId {
        let id = SandboxId::new();
        let spec = SandboxSpec {
            id,
            template: "base".into(),
            limits: ResourceLimits::default(),
            workspace: WorkspaceSpec::Tmpfs { size: 268_435_456 },
            env: BTreeMap::new(),
            timeout: Some(Duration::from_secs(30)),
            policy: None, // built-in least-privilege default
        };
        manager.create(spec).expect("sandbox create");
        id
    }

    /// Compile a tiny standalone Rust program with the host's own rustc
    /// (available in any dev/CI environment that can build this crate at
    /// all) into the sandbox's workspace, then execute it there. `src` is
    /// a complete `fn main() { ... }` program; its exit code is returned.
    fn compile_and_run_in_sandbox(manager: &SandboxManager, id: &SandboxId, src: &str) -> i32 {
        let workspace = manager
            .workspace_upper_dir(id)
            .expect("workspace_upper_dir");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");

        let src_path = workspace.join("check.rs");
        std::fs::write(&src_path, src).expect("write check.rs source");

        let bin_path = workspace.join("check");
        // +crt-static: the check program runs inside the sandbox's own
        // rootfs, which may not have a compatible (or any) dynamic libc —
        // a statically-linked binary sidesteps that entirely rather than
        // assuming the base image's glibc matches the host's.
        let status = std::process::Command::new("rustc")
            .arg("-O")
            .arg("-C")
            .arg("target-feature=+crt-static")
            .arg(&src_path)
            .arg("-o")
            .arg(&bin_path)
            .status()
            .expect("invoke rustc to build the in-sandbox check program");
        assert!(
            status.success(),
            "rustc failed to compile the check program"
        );

        manager
            .exec(id, "/workspace/check", &[])
            .expect("exec check program in sandbox")
    }

    #[test]
    fn test_cannot_read_etc_shadow() {
        let manager = SandboxManager::new().expect("SandboxManager::new");
        let id = new_sandbox(&manager);

        let code = compile_and_run_in_sandbox(
            &manager,
            &id,
            r#"
            fn main() {
                match std::fs::read_to_string("/etc/shadow") {
                    Ok(_) => std::process::exit(1), // escaped
                    Err(e) if matches!(e.raw_os_error(), Some(1) | Some(13)) => std::process::exit(0),
                    Err(_) => std::process::exit(2), // unverified
                }
            }
            "#,
        );

        let _ = manager.destroy(&id);
        assert_eq!(
            code, 0,
            "expected /etc/shadow read to be denied (EPERM/EACCES)"
        );
    }

    #[test]
    fn test_cannot_mount() {
        let manager = SandboxManager::new().expect("SandboxManager::new");
        let id = new_sandbox(&manager);

        let code = compile_and_run_in_sandbox(
            &manager,
            &id,
            r#"
            fn main() {
                extern "C" {
                    fn mount(
                        source: *const i8, target: *const i8, fstype: *const i8,
                        flags: u64, data: *const std::ffi::c_void,
                    ) -> i32;
                }
                let target = std::ffi::CString::new("/tmp").unwrap();
                let fstype = std::ffi::CString::new("tmpfs").unwrap();
                let ret = unsafe { mount(std::ptr::null(), target.as_ptr(), fstype.as_ptr(), 0, std::ptr::null()) };
                if ret == 0 {
                    std::process::exit(1); // escaped
                }
                let e = std::io::Error::last_os_error();
                if matches!(e.raw_os_error(), Some(1) | Some(13)) {
                    std::process::exit(0);
                }
                std::process::exit(2);
            }
            "#,
        );

        let _ = manager.destroy(&id);
        assert_eq!(
            code, 0,
            "expected mount() inside the sandbox to be denied (EPERM/EACCES)"
        );
    }

    #[test]
    fn test_confinement_inherited_by_child_process() {
        // bash -> python3 -> subprocess depth-3 inheritance (blueprint W3):
        // simplified here to a direct child process (fork+exec via
        // std::process::Command from inside the sandboxed check program)
        // attempting the same denied read — Landlock is inherited,
        // unrevokable kernel state, so this should deny identically to the
        // top-level process.
        let manager = SandboxManager::new().expect("SandboxManager::new");
        let id = new_sandbox(&manager);

        let code = compile_and_run_in_sandbox(
            &manager,
            &id,
            r#"
            fn main() {
                // The child branch MUST be tested before spawning anything:
                // checking it afterwards makes every generation spawn the
                // next one first, which is an unbounded fork bomb inside a
                // sandbox whose pids.max we are also relying on. Ask "am I
                // the child?" first, do the denied read, and exit.
                if std::env::var("HOSTILE_CHILD").is_ok() {
                    match std::fs::read_to_string("/etc/shadow") {
                        Ok(_) => std::process::exit(1),
                        Err(e) if matches!(e.raw_os_error(), Some(1) | Some(13)) => std::process::exit(0),
                        Err(_) => std::process::exit(2),
                    }
                }

                // Parent: re-exec ourselves as a child to prove the denial is
                // inherited, not just true for the directly-exec'd process,
                // and propagate the child's verdict as our own.
                let exe = match std::env::current_exe() {
                    Ok(e) => e,
                    Err(_) => std::process::exit(2),
                };
                match std::process::Command::new(exe).env("HOSTILE_CHILD", "1").status() {
                    Ok(s) => std::process::exit(s.code().unwrap_or(2)),
                    Err(_) => std::process::exit(2),
                }
            }
            "#,
        );

        let _ = manager.destroy(&id);
        assert_eq!(
            code, 0,
            "expected Landlock denial to be inherited by a child process, not just the top-level exec"
        );
    }
}
