//! Escape test harness.
//!
//! Builds a real, confined sandbox via `aivisor_runtime::manager::SandboxManager`
//! for each scenario, stages the scenario's compiled binary into the
//! sandbox's workspace, executes it there, and reads back the exit code
//! `aivisor-escape-bench`'s `Outcome::print_and_exit` assigns:
//! 0 = BLOCKED (pass), 1 = ESCAPED (fail), 2 = UNVERIFIED (fail — the
//! scenario didn't prove anything, which is not the same as passing).
//!
//! Any ESCAPED or UNVERIFIED result fails the whole run (non-zero exit),
//! unless the scenario is explicitly marked XFAIL for a named phase in
//! `scenarios()` below — there are none today; every scenario here is
//! expected to pass against what this build currently implements.
//!
//! Usage: cargo run --features privileged-tests --bin escape-harness

#[cfg(feature = "privileged-tests")]
mod run {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use aivisor_core::{ResourceLimits, SandboxId, SandboxSpec, WorkspaceSpec};
    use aivisor_runtime::manager::SandboxManager;

    pub struct Scenario {
        pub category: &'static str,
        pub name: &'static str,
        /// Bin target name, exactly as declared in Cargo.toml's [[bin]]
        /// entries — resolved to a real path at runtime via
        /// `sibling_bin_path`, not `env!("CARGO_BIN_EXE_...")`. That macro
        /// is documented for integration tests/benches locating a
        /// package's bin targets; whether it is populated when compiling
        /// ANOTHER `[[bin]]` in the same package (this harness is one) is
        /// not something this change could verify against real Cargo
        /// behavior, so it deliberately isn't relied on here — all bin
        /// targets of one package land in the same `target/<profile>/`
        /// directory as this harness's own executable, which is a
        /// guarantee `current_exe()` can be used to locate directly.
        pub bin_name: &'static str,
        /// Some(phase) marks a scenario as a known, tracked gap rather
        /// than a silent pass/fail — an ESCAPED result on an XFAIL
        /// scenario still prints loudly but does not fail the build.
        pub xfail_phase: Option<u32>,
    }

    pub fn scenarios() -> Vec<Scenario> {
        vec![
            Scenario {
                category: "fs",
                name: "read_shadow",
                bin_name: "aivisor-escape-fs-read-shadow",
                xfail_phase: None,
            },
            Scenario {
                category: "exec",
                name: "exec_denied",
                bin_name: "aivisor-escape-exec-denied",
                xfail_phase: None,
            },
            Scenario {
                category: "net",
                name: "connect_denied",
                bin_name: "aivisor-escape-net-connect-denied",
                xfail_phase: None,
            },
            Scenario {
                category: "priv",
                name: "mount_inside",
                bin_name: "aivisor-escape-priv-mount-inside",
                xfail_phase: None,
            },
        ]
    }

    /// Resolve a sibling bin target's compiled path: same directory as
    /// this harness's own executable (every [[bin]] in a package is
    /// output to the same `target/<profile>/` directory).
    fn sibling_bin_path(bin_name: &str) -> Result<std::path::PathBuf, String> {
        let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let dir = exe
            .parent()
            .ok_or_else(|| "current_exe has no parent directory".to_string())?;
        let candidate = dir.join(bin_name);
        if !candidate.exists() {
            return Err(format!(
                "expected sibling binary at {} — was `cargo build --bin {bin_name}` run? \
                 (escape-harness does not build it on demand)",
                candidate.display()
            ));
        }
        Ok(candidate)
    }

    pub enum ScenarioResult {
        Blocked,
        Escaped,
        Unverified,
        /// The harness itself couldn't run the scenario at all (sandbox
        /// creation failed, staging the binary failed, an unexpected exit
        /// code came back). Distinct from Unverified: this is a harness/
        /// environment problem, not a statement about the security
        /// control under test — but it still fails the run, because an
        /// escape scenario that can't run has not been shown to pass.
        HarnessError(String),
    }

    pub fn run_one(manager: &SandboxManager, sc: &Scenario) -> ScenarioResult {
        let id = SandboxId::new();
        let spec = SandboxSpec {
            id,
            template: "base".into(),
            limits: ResourceLimits::default(),
            workspace: WorkspaceSpec::Tmpfs { size: 268_435_456 },
            env: BTreeMap::new(),
            timeout: Some(Duration::from_secs(30)),
            // No explicit policy: the runtime's built-in least-privilege
            // default applies (see SandboxManager::default_policy) — no
            // /etc access, no network egress, no exec allowlist beyond
            // whatever binary is actually run. That default IS the policy
            // under test here.
            policy: None,
        };

        if let Err(e) = manager.create(spec) {
            return ScenarioResult::HarnessError(format!("create: {e}"));
        }

        let result = (|| -> Result<ScenarioResult, String> {
            let workspace = manager
                .workspace_upper_dir(&id)
                .map_err(|e| format!("workspace_upper_dir: {e}"))?;
            std::fs::create_dir_all(&workspace).map_err(|e| format!("mkdir workspace: {e}"))?;

            let host_bin = sibling_bin_path(sc.bin_name)?;
            let staged = workspace.join("scenario");
            std::fs::copy(&host_bin, &staged).map_err(|e| format!("stage scenario binary: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&staged)
                    .map_err(|e| format!("stat staged binary: {e}"))?
                    .permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&staged, perms)
                    .map_err(|e| format!("chmod staged binary: {e}"))?;
            }

            let code = manager
                .exec(&id, "/workspace/scenario", &[])
                .map_err(|e| format!("exec: {e}"))?;

            Ok(match code {
                0 => ScenarioResult::Blocked,
                1 => ScenarioResult::Escaped,
                2 => ScenarioResult::Unverified,
                other => ScenarioResult::HarnessError(format!("unexpected exit code {other}")),
            })
        })();

        let _ = manager.destroy(&id);

        result.unwrap_or_else(ScenarioResult::HarnessError)
    }

    pub fn main() {
        let manager = match SandboxManager::new() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("FATAL: cannot construct SandboxManager: {e}");
                std::process::exit(1);
            }
        };

        let mut passed = 0u32;
        let mut failed = 0u32;
        let mut xfail = 0u32;

        for sc in scenarios() {
            eprint!("  {}/{} ... ", sc.category, sc.name);
            match run_one(&manager, &sc) {
                ScenarioResult::Blocked => {
                    eprintln!("BLOCKED (pass)");
                    passed += 1;
                }
                ScenarioResult::Escaped => {
                    if let Some(phase) = sc.xfail_phase {
                        eprintln!("ESCAPED (XFAIL(phase{phase}) — known, tracked gap)");
                        xfail += 1;
                    } else {
                        eprintln!("ESCAPED — SECURITY CONTROL FAILED");
                        failed += 1;
                    }
                }
                ScenarioResult::Unverified => {
                    eprintln!(
                        "UNVERIFIED — scenario did not prove anything (counts as failure, not a pass)"
                    );
                    failed += 1;
                }
                ScenarioResult::HarnessError(reason) => {
                    eprintln!("HARNESS ERROR: {reason}");
                    failed += 1;
                }
            }
        }

        eprintln!("\n=== Escape suite: {passed} passed, {failed} failed, {xfail} xfail ===");
        if failed > 0 {
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "privileged-tests")]
fn main() {
    run::main();
}

#[cfg(not(feature = "privileged-tests"))]
fn main() {
    eprintln!("Skipping escape suite: requires --features privileged-tests on Linux");
}
