use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("kernel feature missing: {feature} (min kernel: {min_kernel})")]
    KernelFeatureMissing {
        feature: &'static str,
        min_kernel: &'static str,
    },

    #[error("cgroup setup failed: {0}")]
    CgroupSetup(String),

    #[error("namespace setup failed: {0}")]
    NamespaceSetup(String),

    #[error("mount setup failed: {0}")]
    MountSetup(String),

    #[error("launch failed: {0}")]
    LaunchFailed(String),

    #[error("sandbox OOM killed")]
    OomKilled,

    #[error("sandbox timeout exceeded")]
    Timeout,

    #[error("sandbox already terminated")]
    AlreadyTerminated,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_yaml::Error),

    #[error("invalid policy: {0}")]
    PolicyInvalid(String),

    #[error("resource limit parse error: {0}")]
    LimitParse(String),

    #[error("not supported: {0}")]
    Unsupported(String),
}
