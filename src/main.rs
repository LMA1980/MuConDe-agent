//! MuConDe-agent main daemon binary entry point.

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use muconde_agent::{MuConDeAgent, MuConDeAgentConfig, SystemCommandRunner, SystemHealthProber};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,muconde_agent=debug")),
        )
        .init();

    tracing::info!("Starting MuConDe-agent v{}", muconde_agent::agent_version());

    let node_id = std::env::var("MUCONDE_NODE_ID").unwrap_or_else(|_| "worker-node".into());
    let listen_addr =
        std::env::var("MUCONDE_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8446".into());
    let muconde_root = std::env::var("MUCONDE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/srv/muconde"));

    let tls_ca_path = std::env::var("MUCONDE_TLS_CA_CERT").ok().map(PathBuf::from);
    let tls_cert_path = std::env::var("MUCONDE_TLS_SERVER_CERT")
        .ok()
        .map(PathBuf::from);
    let tls_key_path = std::env::var("MUCONDE_TLS_SERVER_KEY")
        .ok()
        .map(PathBuf::from);

    let config = MuConDeAgentConfig {
        node_id,
        listen_addr,
        muconde_root,
        tls_ca_path,
        tls_cert_path,
        tls_key_path,
        default_warmup_timeout_secs: 30,
        required_consecutive_successes: 3,
        collector_addr: std::env::var("MUOBSERVE_COLLECTOR_ADDR").ok(),
    };

    let runner = Arc::new(SystemCommandRunner::new());
    let prober = Arc::new(SystemHealthProber::new(runner.clone()));
    let agent = MuConDeAgent::new(config, runner, prober);

    agent.run().await?;

    Ok(())
}
