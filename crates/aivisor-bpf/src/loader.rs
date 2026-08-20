use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};

use aivisor_core::Error;
use libbpf_rs::{Link, MapCore, Object, ObjectBuilder, ProgramType};

pub(crate) const PIN_DIR: &str = "/sys/fs/bpf/aivisor";

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

/// The maps declared in `common.h`, which every object includes and which
/// must therefore resolve to one shared instance each.
///
/// This is an explicit list rather than "every map in the object" because
/// libbpf synthesises per-object internal maps for a program's global data
/// — `exec.rodata`, `.bss`, and friends. Those are private to one object by
/// definition: a `.rodata` map is frozen after load, so trying to reuse one
/// across objects fails the whole load with EPERM. Pinning indiscriminately
/// worked only for as long as no BPF program had any global data.
const SHARED_MAPS: &[&str] = &[
    "sandboxes",
    "fs_rules",
    "exec_rules",
    "net_rules",
    "events",
    "scratch",
];

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
            let mut open_obj = ObjectBuilder::default().open_file(&path).map_err(|e| {
                Error::LaunchFailed(format!("open BPF object {}: {e}", path.display()))
            })?;

            // Set a pin path on every map BEFORE loading, so libbpf reuses
            // an existing pin instead of creating a fresh map.
            //
            // This is what makes the five objects share state. Each of
            // them includes common.h and therefore declares its own
            // `sandboxes`, `fs_rules`, ... definitions; without reuse,
            // loading them produces five *independent* maps that happen to
            // have the same names. Userspace would then register a sandbox
            // in whichever copy it opened while the other four programs
            // kept consulting empty maps, took the `if (!ctx) return 0;`
            // path meant for host processes, and enforced nothing at all.
            // Pinning after load (the previous approach) could not fix
            // that: the first object won the pin and the rest silently
            // skipped it because the path already existed.
            for mut map in open_obj.maps_mut() {
                let map_name = map.name().to_string_lossy().into_owned();
                if !SHARED_MAPS.contains(&map_name.as_str()) {
                    continue;
                }
                let pin_path = PathBuf::from(PIN_DIR).join(&map_name);
                map.set_pin_path(&pin_path).map_err(|e| {
                    Error::LaunchFailed(format!(
                        "set pin path {} for map in {name}: {e}",
                        pin_path.display()
                    ))
                })?;
            }

            let obj: Object = open_obj
                .load()
                .map_err(|e| Error::LaunchFailed(format!("load BPF object {name}: {e}")))?;

            for mut prog in obj.progs_mut() {
                match prog.prog_type() {
                    ProgramType::CgroupSockAddr => {
                        // Deferred: attached per-sandbox-cgroup by the
                        // caller via attach_cgroup_program, not here.
                        //
                        // Pinning is what makes that possible at all. The
                        // attach happens later, from a caller that does not
                        // hold this `Object` — `libbpf_rs::Object` is
                        // `!Send`, so it cannot be stashed in a shared
                        // singleton the way the map handles can. The pin is
                        // the only handle that outlives this scope.
                        let prog_name = prog.name().to_string_lossy().into_owned();
                        let pin_path = PathBuf::from(PIN_DIR).join(&prog_name);
                        if pin_path.exists() {
                            // A pin left by a previous load. Removing it
                            // does not disturb anyone still attached to
                            // that program — an attachment holds its own
                            // fd — but it does ensure the name resolves to
                            // the program just loaded against the current
                            // (reused) maps, rather than to an orphan.
                            std::fs::remove_file(&pin_path).map_err(|e| {
                                Error::LaunchFailed(format!(
                                    "remove stale program pin {}: {e}",
                                    pin_path.display()
                                ))
                            })?;
                        }
                        prog.pin(&pin_path).map_err(|e| {
                            Error::LaunchFailed(format!("pin program {}: {e}", pin_path.display()))
                        })?;
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

    /// Kernel map ids for the map called `name`, one per loaded object that
    /// declares it.
    ///
    /// Every entry must be identical. A differing id means that object got
    /// a private copy of the map rather than reusing the shared pin, and a
    /// program reading a private (and therefore permanently empty)
    /// `sandboxes` map treats every sandbox as a host process and enforces
    /// nothing — see the reuse note in `load_and_attach`. Exposed so that
    /// property can be asserted against a live kernel instead of assumed.
    pub fn map_ids(&self, name: &str) -> Result<Vec<u32>, Error> {
        let mut ids = Vec::new();
        for obj in &self._objects {
            for map in obj.maps() {
                if map.name().to_string_lossy() == name {
                    let info = map
                        .info()
                        .map_err(|e| Error::LaunchFailed(format!("map info for {name}: {e}")))?;
                    ids.push(info.info.id);
                }
            }
        }
        Ok(ids)
    }
}

/// RAII handle for a cgroup_sock_addr program attached to one sandbox's
/// cgroup via the raw `bpf_prog_attach`/`bpf_prog_detach2` pair (libbpf-rs's
/// high-level `Program::attach_cgroup` needs a live `ProgramMut` from an
/// still-open `Object`, not just a pinned-path fd, so the raw libbpf-sys
/// calls are used directly here instead). Detaches automatically on drop —
/// Attached for as long as this value lives; detaches on drop.
///
/// The cgroup fd is duplicated rather than borrowed. The caller's fd
/// belongs to the `Cgroup` object, which is dropped during teardown — if
/// this held the raw number, `Drop` would call `bpf_prog_detach2` on a
/// closed (and possibly recycled) descriptor, detaching whatever now
/// happens to live at that number.
pub struct CgroupProgAttachment {
    _prog_fd: std::os::unix::io::OwnedFd,
    cgroup_fd: std::os::unix::io::OwnedFd,
    attach_type: libbpf_sys::bpf_attach_type,
}

impl Drop for CgroupProgAttachment {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libbpf_sys::bpf_prog_detach2(
                self._prog_fd.as_raw_fd(),
                self.cgroup_fd.as_raw_fd(),
                self.attach_type,
            );
        }
    }
}

/// Names of the per-sandbox cgroup programs, paired with the attach type
/// each one expects. Kept next to the attach helper so a rename on the C
/// side surfaces as a load-time "open pinned program" error rather than a
/// sandbox that quietly never gets its egress hooks.
pub const CGROUP_HOOKS: &[(&str, libbpf_sys::bpf_attach_type)] = &[
    ("aivisor_cgroup_connect4", CGROUP_INET4_CONNECT),
    ("aivisor_cgroup_connect6", CGROUP_INET6_CONNECT),
];

/// Attach every per-sandbox cgroup hook to one sandbox's cgroup.
///
/// All-or-nothing: if the second attach fails the first is dropped (and so
/// detached) before returning, because a sandbox with connect4 hooked but
/// not connect6 has an open IPv6 egress path.
pub fn attach_cgroup_hooks(cgroup_fd: RawFd) -> Result<Vec<CgroupProgAttachment>, Error> {
    let mut attachments = Vec::new();
    for (name, attach_type) in CGROUP_HOOKS {
        attachments.push(attach_cgroup_program(name, cgroup_fd, *attach_type)?);
    }
    Ok(attachments)
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

    // Own a copy of the cgroup fd for the lifetime of the attachment; see
    // CgroupProgAttachment.
    let dup = nix::fcntl::fcntl(cgroup_fd, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(0))
        .map_err(|e| Error::LaunchFailed(format!("dup cgroup fd for {program_name}: {e}")))?;
    // SAFETY: fcntl(F_DUPFD_CLOEXEC) just returned this descriptor and no
    // other owner exists for it.
    let owned_cgroup_fd = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(dup) };

    let ret = unsafe {
        libbpf_sys::bpf_prog_attach(
            prog_fd.as_raw_fd(),
            owned_cgroup_fd.as_raw_fd(),
            attach_type,
            0,
        )
    };
    if ret != 0 {
        return Err(Error::LaunchFailed(format!(
            "bpf_prog_attach {program_name}: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(CgroupProgAttachment {
        _prog_fd: prog_fd,
        cgroup_fd: owned_cgroup_fd,
        attach_type,
    })
}
