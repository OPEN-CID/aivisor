use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

use aivisor_core::Error;
use libbpf_rs::{Link, Object, ObjectBuilder, ProgramType};

const PIN_DIR: &str = "/sys/fs/bpf/aivisor";

/// Manages BPF program lifecycle: load, attach, pin.
///
/// Programs are loaded once, at daemon start, from the `.bpf.o` files
/// `build.rs` compiles into `OUT_DIR` — see that file for how they're
/// built (requires clang with a `bpf` target and a `vmlinux.h`; both are
/// CI/host prerequisites documented there, not silently substituted for).
pub struct BpfLoader;

/// LSM programs (see aivisor-bpf/src/bpf/*.bpf.c) are auto-attached at
/// load — SEC("lsm/...") is enough for libbpf to resolve the attach_btf_id
/// and program type on its own. `cgroup/connect4` and `cgroup/connect6`
/// are a different program type (BPF_PROG_TYPE_CGROUP_SOCK_ADDR) that
/// needs an explicit cgroup fd target and is NOT auto-attached here — they
/// are attached per-sandbox, at sandbox creation, via
/// `attach_cgroup_program` below, using the names
/// `LoadedPrograms::pending_cgroup_programs` reports.
const OBJECTS: &[&str] = &["fs", "exec", "net", "priv", "task"];

impl BpfLoader {
    pub fn new() -> Result<Self, Error> {
        Ok(Self)
    }

    /// Load all BPF LSM programs, auto-attach the LSM-type ones, and pin
    /// the shared maps under `/sys/fs/bpf/aivisor/` so other processes
    /// (or a restarted daemon) can find them by path rather than needing a
    /// live fd handed down some other way.
    ///
    /// On aivisord restart: TODO(phase4) — re-attach to already-pinned
    /// programs/links instead of reloading, so running sandboxes are never
    /// briefly unenforced during a daemon restart. This function always
    /// does a fresh load; the pin step is the foundation that a restart
    /// path would build on, not that path itself.
    pub fn load_and_attach() -> Result<LoadedPrograms, Error> {
        let obj_dir = compiled_object_dir()?;

        std::fs::create_dir_all(PIN_DIR)
            .map_err(|e| Error::LaunchFailed(format!("mkdir {PIN_DIR}: {e}")))?;

        let mut objects = Vec::new();
        let mut lsm_links = Vec::new();
        let mut cgroup_progs = Vec::new();

        for name in OBJECTS {
            let path = obj_dir.join(format!("{name}.bpf.o"));
            let open_obj = ObjectBuilder::default().open_file(&path).map_err(|e| {
                Error::LaunchFailed(format!("open BPF object {}: {e}", path.display()))
            })?;
            let mut obj: Object = open_obj
                .load()
                .map_err(|e| Error::LaunchFailed(format!("load BPF object {name}: {e}")))?;

            for mut prog in obj.progs_mut() {
                match prog.prog_type() {
                    ProgramType::CgroupSockAddr => {
                        // Deferred: attached per-sandbox-cgroup by the
                        // caller via attach_cgroup_hooks, not here.
                        let prog_name = prog.name().to_string_lossy().into_owned();
                        cgroup_progs.push((*name, prog_name));
                    }
                    _ => {
                        let link = prog.attach().map_err(|e| {
                            Error::LaunchFailed(format!(
                                "attach {} ({name}): {e}",
                                prog.name().to_string_lossy()
                            ))
                        })?;
                        lsm_links.push(link);
                    }
                }
            }

            for mut map in obj.maps_mut() {
                let pin_path = PathBuf::from(PIN_DIR).join(map.name());
                if pin_path.exists() {
                    // Already pinned from a previous load (e.g. a prior
                    // process that crashed before cleanup) — leave the
                    // existing pin alone rather than fail the whole load;
                    // re-pinning over a live map would fail anyway.
                    continue;
                }
                map.pin(&pin_path).map_err(|e| {
                    Error::LaunchFailed(format!("pin map {}: {e}", pin_path.display()))
                })?;
            }

            objects.push(obj);
        }

        Ok(LoadedPrograms {
            _objects: objects,
            _lsm_links: lsm_links,
            cgroup_progs,
        })
    }
}

/// Where `build.rs` placed the compiled `.bpf.o` files — `OUT_DIR` isn't
/// visible at runtime (it's a build-time-only Cargo env var), so build.rs
/// re-exports it via `AIVISOR_BPF_OUT_DIR` baked in through
/// `println!("cargo:rustc-env=...")`.
fn compiled_object_dir() -> Result<PathBuf, Error> {
    let dir = option_env!("AIVISOR_BPF_OUT_DIR").ok_or_else(|| {
        Error::LaunchFailed(
            "AIVISOR_BPF_OUT_DIR not set at compile time — BPF objects were not built \
             (see aivisor-bpf/build.rs; likely missing clang or vmlinux.h)"
                .into(),
        )
    })?;
    Ok(Path::new(dir).to_path_buf())
}

pub struct LoadedPrograms {
    // Held only to keep the loaded objects (and therefore their maps)
    // alive for the process lifetime — BPF objects/links detach/unload on
    // drop, so this must outlive every sandbox using them.
    _objects: Vec<Object>,
    _lsm_links: Vec<Link>,
    /// (object name, program name) for the cgroup_sock_addr programs that
    /// still need a per-sandbox `attach_cgroup` call.
    cgroup_progs: Vec<(&'static str, String)>,
}

impl LoadedPrograms {
    /// Names of the loaded cgroup/connect4|6-type programs awaiting
    /// per-sandbox attachment — exposed so a caller can locate them again
    /// (libbpf-rs's `Link` type does not implement Clone, so the actual
    /// attach_cgroup call has to happen against the live `Program` handle,
    /// which in this design means re-opening the object per attach; see
    /// the TODO(phase4) note on `load_and_attach` for the fuller pinned-
    /// program lifecycle this will eventually replace).
    pub fn pending_cgroup_programs(&self) -> &[(&'static str, String)] {
        &self.cgroup_progs
    }
}

/// RAII handle for a cgroup_sock_addr program attached to one sandbox's
/// cgroup via the raw `bpf_prog_attach`/`bpf_prog_detach2` pair (libbpf-rs's
/// high-level `Program::attach_cgroup` needs a live `ProgramMut` from an
/// still-open `Object`, not just a pinned-path fd, so the raw libbpf-sys
/// calls are used directly here instead). Detaches automatically on drop —
/// TODO(phase3): call sites in `aivisor-runtime::SandboxManager` at
/// sandbox creation (attach) and destroy (drop this handle) are not wired
/// up yet; this type is the primitive that wiring would use.
pub struct CgroupProgAttachment {
    _prog_fd: std::os::unix::io::OwnedFd,
    cgroup_fd: RawFd,
    attach_type: libbpf_sys::bpf_attach_type,
}

impl Drop for CgroupProgAttachment {
    fn drop(&mut self) {
        unsafe {
            libbpf_sys::bpf_prog_detach2(
                std::os::unix::io::AsRawFd::as_raw_fd(&self._prog_fd),
                self.cgroup_fd,
                self.attach_type,
            );
        }
    }
}

pub const CGROUP_INET4_CONNECT: libbpf_sys::bpf_attach_type = libbpf_sys::BPF_CGROUP_INET4_CONNECT;
pub const CGROUP_INET6_CONNECT: libbpf_sys::bpf_attach_type = libbpf_sys::BPF_CGROUP_INET6_CONNECT;

/// Attach a pinned cgroup_sock_addr program (by its pin path under
/// PIN_DIR) to a specific sandbox's cgroup. Called once per sandbox at
/// creation time, unlike the LSM programs which attach globally once at
/// daemon start.
pub fn attach_cgroup_program(
    program_name: &str,
    cgroup_fd: RawFd,
    attach_type: libbpf_sys::bpf_attach_type,
) -> Result<CgroupProgAttachment, Error> {
    use std::os::unix::io::AsRawFd;

    let pin_path = PathBuf::from(PIN_DIR).join(program_name);
    let prog_fd = libbpf_rs::Program::fd_from_pinned_path(&pin_path).map_err(|e| {
        Error::LaunchFailed(format!("open pinned program {}: {e}", pin_path.display()))
    })?;

    let ret =
        unsafe { libbpf_sys::bpf_prog_attach(prog_fd.as_raw_fd(), cgroup_fd, attach_type, 0) };
    if ret != 0 {
        return Err(Error::LaunchFailed(format!(
            "bpf_prog_attach {program_name}: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(CgroupProgAttachment {
        _prog_fd: prog_fd,
        cgroup_fd,
        attach_type,
    })
}
