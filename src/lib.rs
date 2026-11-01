//! MuConDe-agent: Node-level continuous delivery daemon executing atomic
//! filesystem operations, dual A/B root subvolume switching, health probes,
//! and autonomous watchdog rollbacks.

#![deny(unsafe_code)]

pub mod agent;
pub mod btrfs;
pub mod error;
pub mod slot;
pub mod watchdog;

pub use agent::{build_tls_server_config, MuConDeAgent, MuConDeAgentConfig};
pub use btrfs::{
    validate_service_name, BtrfsManager, CommandOutput, CommandRunner, MockCommandRunner,
    SystemCommandRunner, ALLOWED_SERVICES,
};
pub use error::AgentError;
pub use slot::{Slot, SlotManager, SwapReceipt};
pub use watchdog::{
    now_epoch_ms, HealthProber, MockHealthProber, ProbeResult, SystemHealthProber, WatchdogMonitor,
    WatchdogOutcome,
};

/// Returns the compiled crate version.
pub fn agent_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
