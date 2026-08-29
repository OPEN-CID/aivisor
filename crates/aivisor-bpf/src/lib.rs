pub mod audit;
pub mod loader;
pub mod maps;

#[cfg(target_os = "linux")]
pub use audit::start_consumer;
pub use audit::{AuditEvent, AuditStream, EventDecision, EventKind, DEFAULT_CHANNEL_DEPTH};
pub use loader::{
    attach_cgroup_hooks, attach_cgroup_program, BpfLoader, CgroupProgAttachment, LoadedPrograms,
    CGROUP_HOOKS, CGROUP_INET4_CONNECT, CGROUP_INET6_CONNECT,
};
pub use maps::{BpfManager, ExecSource, SandboxCtx, TurnOutcome, MAX_RULES_PER_SANDBOX};
