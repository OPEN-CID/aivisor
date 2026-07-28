use std::time::Instant;

use aivisor_core::{ResourceLimits, SandboxId, SandboxSpec, WorkspaceSpec};
use aivisor_runtime::manager::SandboxManager;
use aivisor_runtime::probe;
use clap::{Parser, Subcommand};
use serde_json::json;

#[derive(Parser)]
#[command(
    name = "aivisor",
    about = "Lightweight eBPF-driven sandbox runtime for AI agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check kernel capability requirements
    Doctor,
    /// Run a command inside a sandbox
    Run {
        #[arg(long, default_value = "base")]
        template: String,
        #[arg(long)]
        cpu: Option<String>,
        #[arg(long)]
        memory: Option<String>,
        #[arg(long)]
        pids: Option<u64>,
        #[arg(long)]
        workspace_size: Option<String>,
        #[arg(long)]
        timeout: Option<String>,
        #[arg(long)]
        json: bool,
        /// Path to a SandboxPolicy YAML document (blueprint.md §8.2). If
        /// omitted, the runtime's built-in least-privilege default applies
        /// (workspace read-write, base image read+execute, network
        /// deny-all) — there is no unconfined mode.
        #[arg(long)]
        policy: Option<std::path::PathBuf>,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// List running sandboxes
    Ps,
    /// Execute a command in an existing sandbox
    Exec {
        id: String,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Pause a sandbox
    Pause { id: String },
    /// Resume a sandbox
    Resume { id: String },
    /// Destroy a sandbox
    Destroy { id: String },
    /// Inspect a sandbox
    Inspect { id: String },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Doctor => cmd_doctor(),
        Commands::Run {
            template,
            cpu,
            memory,
            pids,
            workspace_size,
            timeout,
            json,
            policy,
            cmd,
        } => cmd_run(
            template,
            cpu,
            memory,
            pids,
            workspace_size,
            timeout,
            json,
            policy,
            cmd,
        ),
        Commands::Ps => cmd_ps(),
        Commands::Exec { id, cmd } => cmd_exec(&id, cmd),
        Commands::Pause { id } => cmd_pause(&id),
        Commands::Resume { id } => cmd_resume(&id),
        Commands::Destroy { id } => cmd_destroy(&id),
        Commands::Inspect { id } => cmd_inspect(&id),
    }
}

fn state_dir() -> std::path::PathBuf {
    std::path::PathBuf::from("/run/aivisor")
}

/// Honest limitation: `save_manager`/`load_manager` do NOT give sandboxes
/// created by one CLI invocation visibility to a later, separate
/// invocation. `SandboxManager`'s registry is in-memory and process-local;
/// `save_manager` writes a JSON snapshot of `manager.list()` for
/// inspection, but `load_manager` never reads it back into a live
/// registry (there is nothing to reconstruct a `Cgroup`/`Rootfs`/`Launcher`
/// handle FROM — those aren't serializable). Concretely: `aivisor run`
/// works correctly (create, exec, destroy all happen inside one process),
/// but `aivisor ps` / `aivisor exec <id>` / `aivisor pause|resume|destroy
/// <id>` run against sandboxes from an EARLIER `aivisor run` process will
/// not find them — this needs a real daemon all CLI invocations talk to
/// (aivisord + gRPC, TODO(phase4)), not a bigger snapshot file. Documented
/// here rather than silently shipped as if `ps`/`exec` against another
/// process's sandboxes worked.
fn save_manager(manager: &SandboxManager) {
    let dir = state_dir();
    let _ = std::fs::create_dir_all(&dir);
    let state_path = dir.join("state.json");
    if let Ok(list) = serde_json::to_string(&manager.list()) {
        let _ = std::fs::write(&state_path, &list);
    }
}

fn load_manager() -> SandboxManager {
    SandboxManager::new().unwrap_or_else(|e| {
        eprintln!("FATAL: kernel requirements not met: {e}");
        std::process::exit(1);
    })
}

fn cmd_doctor() -> anyhow::Result<()> {
    let caps = probe::probe_all();

    println!("AIVisor Kernel Capability Report");
    println!("================================\n");

    println!("Kernel: {}.{}", caps.kernel.0, caps.kernel.1);
    println!("cgroup v2:              {}", bool_emoji(caps.cgroup_v2));
    println!("clone3:                 {}", bool_emoji(caps.clone3));
    println!(
        "CLONE_INTO_CGROUP:      {}",
        bool_emoji(caps.clone_into_cgroup)
    );
    println!("cgroup.kill:            {}", bool_emoji(caps.cgroup_kill));
    println!("overlayfs:              {}", bool_emoji(caps.overlayfs));
    println!(
        "overlayfs in userns:    {}",
        bool_emoji(caps.overlayfs_in_userns)
    );
    println!(
        "unprivileged userns:    {}",
        bool_emoji(caps.unprivileged_userns)
    );
    println!("Controllers:            {:?}", caps.controllers);

    match probe::check_hard_requirements(&caps) {
        Ok(()) => {
            println!("\n✓ All hard requirements met");
            Ok(())
        }
        Err(msg) => {
            eprintln!("\n✗ {msg}");
            std::process::exit(1);
        }
    }
}

const CLI_POLICY_NAME: &str = "cli-policy";

fn cmd_run(
    template: String,
    cpu: Option<String>,
    memory: Option<String>,
    pids: Option<u64>,
    workspace_size: Option<String>,
    timeout: Option<String>,
    json: bool,
    policy: Option<std::path::PathBuf>,
    cmd: Vec<String>,
) -> anyhow::Result<()> {
    if cmd.first().map_or(true, |c| !c.starts_with('/')) {
        anyhow::bail!(
            "cmd must be an absolute path inside the sandbox (e.g. /usr/bin/python3, not \
             python3) — aivisor does not perform PATH lookup"
        );
    }

    let start = Instant::now();

    let manager = load_manager();

    let policy_ref = match policy {
        Some(path) => {
            let compiled = aivisor_policy::parse_policy(&path)
                .map_err(|e| anyhow::anyhow!("policy {}: {e}", path.display()))?;
            manager.register_policy(CLI_POLICY_NAME.into(), compiled);
            Some(aivisor_core::PolicyRef {
                name: CLI_POLICY_NAME.into(),
                overrides: None,
            })
        }
        None => None,
    };

    let t_cgroup = start.elapsed().as_micros();

    let id = SandboxId::new();
    let mut limits = ResourceLimits::default();

    if let Some(ref cpu_str) = cpu {
        let cpus: f64 = cpu_str.parse()?;
        limits.cpu_max = Some(aivisor_core::CpuQuota::from_cpus(cpus));
    }

    if let Some(ref mem_str) = memory {
        limits.memory_max = Some(parse_size(mem_str).map_err(|e| anyhow::anyhow!(e))?);
        limits.memory_high = Some(limits.memory_max.unwrap() * 9 / 10);
    }

    if let Some(p) = pids {
        limits.pids_max = Some(p);
    }

    let ws_size = workspace_size
        .as_ref()
        .map(|s| parse_size(s).unwrap_or(1073741824))
        .unwrap_or(1073741824);

    let spec = SandboxSpec {
        id,
        template,
        limits,
        workspace: WorkspaceSpec::Tmpfs { size: ws_size },
        env: std::collections::BTreeMap::new(),
        timeout: timeout.as_ref().and_then(|t| parse_duration(t).ok()),
        policy: policy_ref,
    };

    let t_create = start.elapsed().as_micros();
    manager.create(spec)?;
    save_manager(&manager);

    let t_ready = start.elapsed().as_micros();

    if json {
        let report = json!({
            "sandbox_id": id.to_string(),
            "t_cgroup_us": t_cgroup,
            "t_create_us": t_create,
            "t_ready_us": t_ready,
        });
        println!("{}", report);
    }

    let exit_code = manager.exec(&id, &cmd[0], &cmd[1..]).unwrap_or(-1);
    let _ = manager.destroy(&id);
    save_manager(&manager);
    std::process::exit(exit_code);
}

fn cmd_ps() -> anyhow::Result<()> {
    let manager = load_manager();
    let list = manager.list();
    if list.is_empty() {
        println!("No running sandboxes");
    } else {
        println!("{:<40} {:<15} {}", "ID", "STATE", "TEMPLATE");
        println!("{}", "-".repeat(75));
        for sb in &list {
            println!("{:<40} {:<15?} {}", sb.id, sb.state, sb.template);
        }
    }
    Ok(())
}

fn cmd_exec(id: &str, cmd: Vec<String>) -> anyhow::Result<()> {
    let manager = load_manager();
    let sid = parse_sandbox_id(id)?;
    let code = manager.exec(&sid, &cmd[0], &cmd[1..])?;
    save_manager(&manager);
    std::process::exit(code);
}

fn cmd_pause(id: &str) -> anyhow::Result<()> {
    let manager = load_manager();
    let sid = parse_sandbox_id(id)?;
    manager.pause(&sid)?;
    save_manager(&manager);
    println!("Paused {}", id);
    Ok(())
}

fn cmd_resume(id: &str) -> anyhow::Result<()> {
    let manager = load_manager();
    let sid = parse_sandbox_id(id)?;
    manager.resume(&sid)?;
    save_manager(&manager);
    println!("Resumed {}", id);
    Ok(())
}

fn cmd_destroy(id: &str) -> anyhow::Result<()> {
    let manager = load_manager();
    let sid = parse_sandbox_id(id)?;
    manager.destroy(&sid)?;
    save_manager(&manager);
    println!("Destroyed {}", id);
    Ok(())
}

fn cmd_inspect(id: &str) -> anyhow::Result<()> {
    let manager = load_manager();
    let sid = parse_sandbox_id(id)?;
    let list = manager.list();
    for sb in &list {
        if sb.id == sid {
            println!("ID:       {}", sb.id);
            println!("State:    {:?}", sb.state);
            println!("Template: {}", sb.template);
            return Ok(());
        }
    }
    eprintln!("sandbox not found: {id}");
    std::process::exit(1);
}

fn parse_sandbox_id(s: &str) -> anyhow::Result<SandboxId> {
    let uuid = uuid::Uuid::parse_str(s)?;
    Ok(SandboxId::from_bytes(*uuid.as_bytes()))
}

fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num_str, unit) = if s.ends_with("Gi") {
        (&s[..s.len() - 2], 1073741824u64)
    } else if s.ends_with("Mi") {
        (&s[..s.len() - 2], 1048576u64)
    } else if s.ends_with("Ki") {
        (&s[..s.len() - 2], 1024u64)
    } else if s.ends_with('G') {
        (&s[..s.len() - 1], 1000000000u64)
    } else if s.ends_with('M') {
        (&s[..s.len() - 1], 1000000u64)
    } else if s.ends_with('K') {
        (&s[..s.len() - 1], 1000u64)
    } else {
        (s, 1)
    };
    let num: f64 = num_str.parse().map_err(|_| format!("invalid size: {s}"))?;
    Ok((num * unit as f64) as u64)
}

fn parse_duration(s: &str) -> Result<std::time::Duration, String> {
    let s = s.trim();
    if s.ends_with('s') {
        let secs: u64 = s[..s.len() - 1]
            .parse()
            .map_err(|_| format!("invalid duration: {s}"))?;
        Ok(std::time::Duration::from_secs(secs))
    } else if s.ends_with("ms") {
        let ms: u64 = s[..s.len() - 2]
            .parse()
            .map_err(|_| format!("invalid duration: {s}"))?;
        Ok(std::time::Duration::from_millis(ms))
    } else if s.ends_with('m') {
        let mins: u64 = s[..s.len() - 1]
            .parse()
            .map_err(|_| format!("invalid duration: {s}"))?;
        Ok(std::time::Duration::from_secs(mins * 60))
    } else if s.ends_with('h') {
        let hrs: u64 = s[..s.len() - 1]
            .parse()
            .map_err(|_| format!("invalid duration: {s}"))?;
        Ok(std::time::Duration::from_secs(hrs * 3600))
    } else {
        Err(format!("invalid duration: {s}"))
    }
}

fn bool_emoji(v: bool) -> &'static str {
    if v {
        "✓"
    } else {
        "✗"
    }
}
