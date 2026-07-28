use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxState {
    Provisioning,
    Ready,
    Running,
    Paused,
    Checkpointing,
    Restoring,
    Terminating,
    Terminated,
}
