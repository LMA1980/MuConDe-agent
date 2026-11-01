//! Network IPC agent daemon receiving controller deployment RPCs and managing node lifecycle.

#![deny(unsafe_code)]

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use muconde_ipc::framing::{
    read_frame, write_frame, IpcHeader, MSG_TYPE_ARTIFACT_TAINT, MSG_TYPE_HEALTH_PROBE,
    MSG_TYPE_HEARTBEAT, MSG_TYPE_IT_REPORT, MSG_TYPE_ROLLBACK, MSG_TYPE_SLOT_SWAP,
    MSG_TYPE_STAGE_DEPLOY_REQ, MSG_TYPE_STAGE_DEPLOY_RESP,
};
use muconde_ipc::{
    create_fory_runtime, HeartbeatTelemetry, RollbackCommand, SlotSwapCommand,
    StageDeploymentRequest,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

use crate::btrfs::{BtrfsManager, CommandRunner, SystemCommandRunner};
use crate::error::AgentError;
use crate::slot::{Slot, SlotManager};
use crate::telemetry::{
    now_unix_nano, trace_context_for_deployment, MuObserveCollectorSink, TelemetrySink,
    AGENT_SERVICE_NAME,
};
use crate::watchdog::{
    now_epoch_ms, HealthProber, SystemHealthProber, WatchdogMonitor, WatchdogOutcome,
};
use muobserve_ipc::{OtelMetricEntry, OtelSpanEntry};

/// Configuration parameters for the MuConDe node agent daemon.
#[derive(Debug, Clone)]
pub struct MuConDeAgentConfig {
    pub node_id: String,
    pub listen_addr: String,
    pub muconde_root: PathBuf,
    pub tls_ca_path: Option<PathBuf>,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub default_warmup_timeout_secs: u64,
    pub required_consecutive_successes: u32,
    pub collector_addr: Option<String>,
}

impl Default for MuConDeAgentConfig {
    fn default() -> Self {
        Self {
            node_id: "worker-node".into(),
            listen_addr: "0.0.0.0:8446".into(),
            muconde_root: PathBuf::from("/srv/muconde"),
            tls_ca_path: None,
            tls_cert_path: None,
            tls_key_path: None,
            default_warmup_timeout_secs: 30,
            required_consecutive_successes: 3,
            collector_addr: std::env::var("MUOBSERVE_COLLECTOR_ADDR").ok(),
        }
    }
}

/// Builds rustls ServerConfig enforcing mutual TLS (mTLS) with client certificate verification.
pub fn build_tls_server_config(
    ca_cert_path: impl AsRef<Path>,
    server_cert_path: impl AsRef<Path>,
    server_key_path: impl AsRef<Path>,
) -> Result<rustls::ServerConfig, AgentError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ca_file = File::open(ca_cert_path.as_ref()).map_err(AgentError::Io)?;
    let mut ca_reader = BufReader::new(ca_file);
    let ca_certs: Vec<CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_reader_iter(&mut ca_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AgentError::Tls(format!("Failed to parse CA certificate PEM: {e}")))?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|e| AgentError::Tls(format!("Failed to add CA cert to root store: {e}")))?;
    }

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| AgentError::Tls(format!("Failed to build client verifier: {e}")))?;

    let srv_file = File::open(server_cert_path.as_ref()).map_err(AgentError::Io)?;
    let mut srv_reader = BufReader::new(srv_file);
    let srv_certs: Vec<CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_reader_iter(&mut srv_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AgentError::Tls(format!("Failed to parse server cert PEM: {e}")))?;

    let key_file = File::open(server_key_path.as_ref()).map_err(AgentError::Io)?;
    let mut key_reader = BufReader::new(key_file);
    let key: PrivateKeyDer<'static> =
        rustls_pki_types::PrivateKeyDer::from_pem_reader(&mut key_reader)
            .map_err(|e| AgentError::Tls(format!("Failed to parse server private key: {e}")))?;

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(srv_certs, key)
        .map_err(|e| AgentError::Tls(format!("Failed to configure server cert: {e}")))?;

    Ok(config)
}

/// Continuous delivery node agent running as a resident systemd daemon.
pub struct MuConDeAgent {
    config: MuConDeAgentConfig,
    btrfs_manager: Arc<BtrfsManager>,
    slot_manager: Arc<SlotManager>,
    watchdog_monitor: Arc<WatchdogMonitor>,
    telemetry_sink: Arc<dyn TelemetrySink>,
}

impl MuConDeAgent {
    pub fn new(
        config: MuConDeAgentConfig,
        runner: Arc<dyn CommandRunner>,
        prober: Arc<dyn HealthProber>,
    ) -> Self {
        let btrfs_manager = Arc::new(BtrfsManager::new(&config.muconde_root, runner.clone()));
        let slot_manager = Arc::new(SlotManager::new(&config.muconde_root, runner));
        let watchdog_monitor = Arc::new(WatchdogMonitor::new(
            &config.node_id,
            slot_manager.clone(),
            prober,
        ));
        let telemetry_sink = Arc::new(MuObserveCollectorSink::new(config.collector_addr.clone()));

        Self {
            config,
            btrfs_manager,
            slot_manager,
            watchdog_monitor,
            telemetry_sink,
        }
    }

    /// Replaces the default `MuObserveCollectorSink` with a custom [`TelemetrySink`].
    #[must_use]
    pub fn with_telemetry_sink(mut self, telemetry_sink: Arc<dyn TelemetrySink>) -> Self {
        self.telemetry_sink = telemetry_sink;
        self
    }

    pub fn telemetry_sink(&self) -> &Arc<dyn TelemetrySink> {
        &self.telemetry_sink
    }

    pub fn default_with_root(node_id: &str, root: PathBuf) -> Self {
        let runner = Arc::new(SystemCommandRunner::new());
        let prober = Arc::new(SystemHealthProber::new(runner.clone()));
        let config = MuConDeAgentConfig {
            node_id: node_id.to_string(),
            muconde_root: root,
            ..Default::default()
        };
        Self::new(config, runner, prober)
    }

    pub fn config(&self) -> &MuConDeAgentConfig {
        &self.config
    }

    pub fn btrfs_manager(&self) -> &Arc<BtrfsManager> {
        &self.btrfs_manager
    }

    pub fn slot_manager(&self) -> &Arc<SlotManager> {
        &self.slot_manager
    }

    pub fn watchdog_monitor(&self) -> &Arc<WatchdogMonitor> {
        &self.watchdog_monitor
    }

    /// Handles a single incoming IPC bidirectional connection stream.
    pub async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut stream: S,
    ) -> Result<(), AgentError> {
        let fory = create_fory_runtime()?;

        loop {
            let (header, payload) = match read_frame(&mut stream).await {
                Ok(frame) => frame,
                Err(muconde_ipc::IpcError::Io(ref e))
                    if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    tracing::debug!("Client disconnected cleanly");
                    return Ok(());
                }
                Err(e) => return Err(AgentError::Ipc(e)),
            };

            match header.msg_type {
                MSG_TYPE_STAGE_DEPLOY_REQ => {
                    let req: StageDeploymentRequest = fory
                        .deserialize(&payload)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;

                    tracing::info!(
                        deployment_id = %req.deployment_id,
                        service = %req.service_name,
                        slot = ?req.target_slot,
                        "Received StageDeploymentRequest"
                    );

                    let start_ns = now_unix_nano();
                    let trace_ctx = trace_context_for_deployment(&req.deployment_id, 1);

                    // Locate staging candidate binary path
                    let candidate_path = self
                        .config
                        .muconde_root
                        .join("staging")
                        .join(&req.artifact_sha256);

                    let resp = self.btrfs_manager.handle_stage_deployment_request(
                        &req,
                        &candidate_path,
                        "",
                    );
                    let end_ns = now_unix_nano().max(start_ns);
                    let duration_ns = (end_ns - start_ns) as u64;

                    let span = OtelSpanEntry {
                        trace_id: trace_ctx.trace_id_hex(),
                        span_id: trace_ctx.span_id_hex(),
                        parent_span_id: None,
                        service_name: AGENT_SERVICE_NAME.to_string(),
                        node_id: self.config.node_id.clone(),
                        span_name: "muconde.agent.stage_deployment".to_string(),
                        span_kind: "SERVER".to_string(),
                        start_time_unix_nano: start_ns,
                        end_time_unix_nano: end_ns,
                        duration_ns,
                        status_code: if resp.staged_ok { "OK" } else { "ERROR" }.to_string(),
                        status_message: resp.error_message.clone(),
                        attributes_json: serde_json::json!({
                            "deployment_id": req.deployment_id,
                            "lease_id": req.lease_id,
                            "service_name": req.service_name,
                            "artifact_sha256": req.artifact_sha256,
                            "target_slot": format!("{:?}", req.target_slot),
                            "btrfs_subvolume_path": resp.btrfs_subvolume_path,
                            "staged_ok": resp.staged_ok,
                        })
                        .to_string(),
                    };

                    let metric = OtelMetricEntry {
                        timestamp_unix_nano: end_ns,
                        service_name: AGENT_SERVICE_NAME.to_string(),
                        node_id: self.config.node_id.clone(),
                        metric_name: "muconde.agent.stage_duration_ms".to_string(),
                        metric_unit: "ms".to_string(),
                        value_f64: (duration_ns as f64) / 1_000_000.0,
                        arch: std::env::consts::ARCH.to_string(),
                        cpu_cluster: None,
                        vlen_bits: None,
                        memlock_used_bytes: None,
                        memlock_limit_bytes: None,
                        trace_id: Some(trace_ctx.trace_id_hex()),
                        span_id: Some(trace_ctx.span_id_hex()),
                        attributes_json: serde_json::json!({
                            "deployment_id": req.deployment_id,
                            "service_name": req.service_name,
                            "staged_ok": resp.staged_ok,
                        })
                        .to_string(),
                    };

                    self.telemetry_sink.emit_spans(vec![span]).await;
                    self.telemetry_sink.emit_metrics(vec![metric]).await;

                    let resp_bytes = fory
                        .serialize(&resp)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;

                    let resp_header = IpcHeader::new(
                        MSG_TYPE_STAGE_DEPLOY_RESP,
                        resp_bytes.len() as u32,
                        0,
                        header.sequence,
                    );

                    write_frame(&mut stream, &resp_header, &resp_bytes).await?;
                }

                MSG_TYPE_SLOT_SWAP => {
                    let cmd: SlotSwapCommand = fory
                        .deserialize(&payload)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;

                    tracing::info!(
                        deployment_id = %cmd.deployment_id,
                        service = %cmd.service_name,
                        target_slot = ?cmd.to_slot,
                        "Received SlotSwapCommand"
                    );

                    let swap_start_ns = now_unix_nano();
                    let swap_trace_ctx = trace_context_for_deployment(&cmd.deployment_id, 2);

                    // 1. Perform atomic pointer swap
                    let target_slot = Slot::from(cmd.to_slot);
                    let _receipt = self
                        .slot_manager
                        .atomic_swap_active_slot(&cmd.service_name, target_slot)?;

                    let swap_end_ns = now_unix_nano().max(swap_start_ns);
                    let swap_dur_ns = (swap_end_ns - swap_start_ns) as u64;

                    let swap_span = OtelSpanEntry {
                        trace_id: swap_trace_ctx.trace_id_hex(),
                        span_id: swap_trace_ctx.span_id_hex(),
                        parent_span_id: None,
                        service_name: AGENT_SERVICE_NAME.to_string(),
                        node_id: self.config.node_id.clone(),
                        span_name: "muconde.agent.slot_swap".to_string(),
                        span_kind: "SERVER".to_string(),
                        start_time_unix_nano: swap_start_ns,
                        end_time_unix_nano: swap_end_ns,
                        duration_ns: swap_dur_ns,
                        status_code: "OK".to_string(),
                        status_message: None,
                        attributes_json: serde_json::json!({
                            "deployment_id": cmd.deployment_id,
                            "lease_id": cmd.lease_id,
                            "service_name": cmd.service_name,
                            "from_slot": format!("{:?}", cmd.from_slot),
                            "to_slot": format!("{:?}", cmd.to_slot),
                            "subvolume": target_slot.as_str(),
                            "systemd_unit": cmd.systemd_unit,
                        })
                        .to_string(),
                    };

                    let slot_metric = OtelMetricEntry {
                        timestamp_unix_nano: swap_end_ns,
                        service_name: AGENT_SERVICE_NAME.to_string(),
                        node_id: self.config.node_id.clone(),
                        metric_name: "muconde.agent.active_slot".to_string(),
                        metric_unit: "slot".to_string(),
                        value_f64: match target_slot {
                            Slot::A => 0.0,
                            Slot::B => 1.0,
                        },
                        arch: std::env::consts::ARCH.to_string(),
                        cpu_cluster: None,
                        vlen_bits: None,
                        memlock_used_bytes: None,
                        memlock_limit_bytes: None,
                        trace_id: Some(swap_trace_ctx.trace_id_hex()),
                        span_id: Some(swap_trace_ctx.span_id_hex()),
                        attributes_json: serde_json::json!({
                            "deployment_id": cmd.deployment_id,
                            "service_name": cmd.service_name,
                            "subvolume": target_slot.as_str(),
                        })
                        .to_string(),
                    };

                    self.telemetry_sink.emit_spans(vec![swap_span]).await;
                    self.telemetry_sink.emit_metrics(vec![slot_metric]).await;

                    // 2. Start warmup watchdog monitoring
                    let (tx, mut rx) = mpsc::channel(32);
                    let monitor = self.watchdog_monitor.clone();
                    let cmd_clone = cmd.clone();
                    let consecutive_req = self.config.required_consecutive_successes;
                    let expires_at_ms = now_epoch_ms() + (cmd.warmup_timeout_secs * 1000);

                    let outcome_task = tokio::spawn(async move {
                        monitor
                            .monitor_warmup(
                                &cmd_clone,
                                "candidate-sha",
                                expires_at_ms,
                                consecutive_req,
                                Some(tx),
                                None,
                            )
                            .await
                    });

                    // Forward telemetry ticks over stream and emit OtelMetricEntry batches
                    while let Some(telem) = rx.recv().await {
                        let ts_ns = now_unix_nano();
                        let probe_attrs = serde_json::json!({
                            "deployment_id": telem.deployment_id,
                            "service_name": telem.service_name,
                            "active_slot": format!("{:?}", telem.active_slot),
                            "systemd_active": telem.systemd_active,
                            "health_endpoint_ok": telem.health_endpoint_ok,
                        })
                        .to_string();

                        let probe_metrics = vec![
                            OtelMetricEntry {
                                timestamp_unix_nano: ts_ns,
                                service_name: AGENT_SERVICE_NAME.to_string(),
                                node_id: self.config.node_id.clone(),
                                metric_name: "muconde.agent.slot_probe_latency_ms".to_string(),
                                metric_unit: "ms".to_string(),
                                value_f64: f64::from(telem.probe_latency_ms),
                                arch: std::env::consts::ARCH.to_string(),
                                cpu_cluster: None,
                                vlen_bits: None,
                                memlock_used_bytes: None,
                                memlock_limit_bytes: None,
                                trace_id: Some(swap_trace_ctx.trace_id_hex()),
                                span_id: Some(swap_trace_ctx.span_id_hex()),
                                attributes_json: probe_attrs.clone(),
                            },
                            OtelMetricEntry {
                                timestamp_unix_nano: ts_ns,
                                service_name: AGENT_SERVICE_NAME.to_string(),
                                node_id: self.config.node_id.clone(),
                                metric_name: "muconde.agent.slot_probe_healthy".to_string(),
                                metric_unit: "1".to_string(),
                                value_f64: if telem.systemd_active && telem.health_endpoint_ok {
                                    1.0
                                } else {
                                    0.0
                                },
                                arch: std::env::consts::ARCH.to_string(),
                                cpu_cluster: None,
                                vlen_bits: None,
                                memlock_used_bytes: None,
                                memlock_limit_bytes: None,
                                trace_id: Some(swap_trace_ctx.trace_id_hex()),
                                span_id: Some(swap_trace_ctx.span_id_hex()),
                                attributes_json: probe_attrs,
                            },
                        ];
                        self.telemetry_sink.emit_metrics(probe_metrics).await;

                        let telem_bytes = fory
                            .serialize(&telem)
                            .map_err(|e| AgentError::Serialization(e.to_string()))?;
                        let telem_header = IpcHeader::new(
                            MSG_TYPE_HEALTH_PROBE,
                            telem_bytes.len() as u32,
                            0,
                            header.sequence,
                        );
                        let _ = write_frame(&mut stream, &telem_header, &telem_bytes).await;
                    }

                    match outcome_task.await {
                        Ok(Ok(WatchdogOutcome::RolledBack {
                            report,
                            taint,
                            elapsed_rollback_ms,
                        })) => {
                            let rb_ctx = swap_trace_ctx.next_deterministic_child(1);
                            let rb_end_ns = now_unix_nano().max(swap_end_ns);
                            let rb_span = OtelSpanEntry {
                                trace_id: rb_ctx.trace_id_hex(),
                                span_id: rb_ctx.span_id_hex(),
                                parent_span_id: Some(swap_trace_ctx.span_id_hex()),
                                service_name: AGENT_SERVICE_NAME.to_string(),
                                node_id: self.config.node_id.clone(),
                                span_name: "muconde.agent.rollback".to_string(),
                                span_kind: "INTERNAL".to_string(),
                                start_time_unix_nano: swap_end_ns,
                                end_time_unix_nano: rb_end_ns,
                                duration_ns: elapsed_rollback_ms * 1_000_000,
                                status_code: "ERROR".to_string(),
                                status_message: Some(taint.reason.clone()),
                                attributes_json: serde_json::json!({
                                    "deployment_id": cmd.deployment_id,
                                    "service_name": cmd.service_name,
                                    "restore_slot": "@a",
                                    "reason": taint.reason,
                                    "elapsed_rollback_ms": elapsed_rollback_ms,
                                })
                                .to_string(),
                            };
                            self.telemetry_sink.emit_spans(vec![rb_span]).await;

                            // Send IntegrationTestReport
                            let report_bytes = fory
                                .serialize(&*report)
                                .map_err(|e| AgentError::Serialization(e.to_string()))?;
                            let report_header = IpcHeader::new(
                                MSG_TYPE_IT_REPORT,
                                report_bytes.len() as u32,
                                0,
                                header.sequence,
                            );
                            write_frame(&mut stream, &report_header, &report_bytes).await?;

                            // Send ArtifactTaintNotification
                            let taint_bytes = fory
                                .serialize(&*taint)
                                .map_err(|e| AgentError::Serialization(e.to_string()))?;
                            let taint_header = IpcHeader::new(
                                MSG_TYPE_ARTIFACT_TAINT,
                                taint_bytes.len() as u32,
                                0,
                                header.sequence,
                            );
                            write_frame(&mut stream, &taint_header, &taint_bytes).await?;
                        }
                        Ok(Ok(WatchdogOutcome::WarmedUp { .. })) => {
                            tracing::info!(
                                deployment_id = %cmd.deployment_id,
                                "Warmup completed successfully"
                            );
                        }
                        Ok(Err(e)) => {
                            tracing::error!("Watchdog error: {}", e);
                        }
                        Err(join_err) => {
                            tracing::error!("Watchdog task join error: {}", join_err);
                        }
                    }
                }

                MSG_TYPE_ROLLBACK => {
                    let cmd: RollbackCommand = fory
                        .deserialize(&payload)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;

                    tracing::warn!(
                        deployment_id = %cmd.deployment_id,
                        service = %cmd.service_name,
                        reason = %cmd.reason,
                        "Received RollbackCommand from controller"
                    );

                    let rb_start_ns = now_unix_nano();
                    let rb_trace_ctx = trace_context_for_deployment(&cmd.deployment_id, 3);

                    let (report, taint, elapsed_ms) =
                        self.watchdog_monitor.handle_rollback_command(&cmd)?;

                    let rb_end_ns = now_unix_nano().max(rb_start_ns);
                    let rb_dur_ns = (rb_end_ns - rb_start_ns) as u64;

                    let rb_span = OtelSpanEntry {
                        trace_id: rb_trace_ctx.trace_id_hex(),
                        span_id: rb_trace_ctx.span_id_hex(),
                        parent_span_id: None,
                        service_name: AGENT_SERVICE_NAME.to_string(),
                        node_id: self.config.node_id.clone(),
                        span_name: "muconde.agent.rollback".to_string(),
                        span_kind: "SERVER".to_string(),
                        start_time_unix_nano: rb_start_ns,
                        end_time_unix_nano: rb_end_ns,
                        duration_ns: rb_dur_ns,
                        status_code: "OK".to_string(),
                        status_message: Some(cmd.reason.clone()),
                        attributes_json: serde_json::json!({
                            "deployment_id": cmd.deployment_id,
                            "lease_id": cmd.lease_id,
                            "service_name": cmd.service_name,
                            "restore_slot": format!("{:?}", cmd.restore_slot),
                            "failed_artifact_sha256": cmd.failed_artifact_sha256,
                            "reason": cmd.reason,
                            "elapsed_rollback_ms": elapsed_ms,
                        })
                        .to_string(),
                    };

                    let rb_metric = OtelMetricEntry {
                        timestamp_unix_nano: rb_end_ns,
                        service_name: AGENT_SERVICE_NAME.to_string(),
                        node_id: self.config.node_id.clone(),
                        metric_name: "muconde.agent.rollback_duration_ms".to_string(),
                        metric_unit: "ms".to_string(),
                        value_f64: elapsed_ms as f64,
                        arch: std::env::consts::ARCH.to_string(),
                        cpu_cluster: None,
                        vlen_bits: None,
                        memlock_used_bytes: None,
                        memlock_limit_bytes: None,
                        trace_id: Some(rb_trace_ctx.trace_id_hex()),
                        span_id: Some(rb_trace_ctx.span_id_hex()),
                        attributes_json: serde_json::json!({
                            "deployment_id": cmd.deployment_id,
                            "service_name": cmd.service_name,
                            "restore_slot": "@a",
                        })
                        .to_string(),
                    };

                    self.telemetry_sink.emit_spans(vec![rb_span]).await;
                    self.telemetry_sink.emit_metrics(vec![rb_metric]).await;

                    let report_bytes = fory
                        .serialize(&report)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;
                    let report_header = IpcHeader::new(
                        MSG_TYPE_IT_REPORT,
                        report_bytes.len() as u32,
                        0,
                        header.sequence,
                    );
                    write_frame(&mut stream, &report_header, &report_bytes).await?;

                    let taint_bytes = fory
                        .serialize(&taint)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;
                    let taint_header = IpcHeader::new(
                        MSG_TYPE_ARTIFACT_TAINT,
                        taint_bytes.len() as u32,
                        0,
                        header.sequence,
                    );
                    write_frame(&mut stream, &taint_header, &taint_bytes).await?;
                }

                MSG_TYPE_HEARTBEAT => {
                    let hb = HeartbeatTelemetry {
                        node_id: self.config.node_id.clone(),
                        active_deployments: 0,
                        btrfs_free_bytes: 100 * 1024 * 1024 * 1024,
                        timestamp_epoch_ms: now_epoch_ms(),
                    };
                    let hb_bytes = fory
                        .serialize(&hb)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;
                    let hb_header = IpcHeader::new(
                        MSG_TYPE_HEARTBEAT,
                        hb_bytes.len() as u32,
                        0,
                        header.sequence,
                    );
                    write_frame(&mut stream, &hb_header, &hb_bytes).await?;
                }

                other => {
                    tracing::warn!("Unrecognized message type: 0x{:02X}", other);
                }
            }
        }
    }

    /// Daemon listener loop binding to `config.listen_addr` and serving incoming connections.
    pub async fn run(&self) -> Result<(), AgentError> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        tracing::info!(
            addr = %self.config.listen_addr,
            node_id = %self.config.node_id,
            "MuConDe-agent daemon listening for controller RPCs"
        );

        let tls_acceptor = if let (Some(ca), Some(cert), Some(key)) = (
            &self.config.tls_ca_path,
            &self.config.tls_cert_path,
            &self.config.tls_key_path,
        ) {
            let tls_config = build_tls_server_config(ca, cert, key)?;
            Some(TlsAcceptor::from(Arc::new(tls_config)))
        } else {
            None
        };

        loop {
            let (stream, remote_addr) = listener.accept().await?;
            tracing::debug!(remote = %remote_addr, "Accepted incoming IPC connection");

            if let Some(ref acceptor) = tls_acceptor {
                let acceptor = acceptor.clone();
                let agent_btrfs = self.btrfs_manager.clone();
                let agent_slot = self.slot_manager.clone();
                let agent_watchdog = self.watchdog_monitor.clone();
                let agent_telemetry = self.telemetry_sink.clone();
                let config = self.config.clone();

                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let agent = MuConDeAgent {
                                config,
                                btrfs_manager: agent_btrfs,
                                slot_manager: agent_slot,
                                watchdog_monitor: agent_watchdog,
                                telemetry_sink: agent_telemetry,
                            };
                            if let Err(e) = agent.handle_connection(tls_stream).await {
                                tracing::error!("Connection error: {}", e);
                            }
                        }
                        Err(e) => {
                            tracing::error!("TLS handshake failed: {}", e);
                        }
                    }
                });
            } else {
                let agent_btrfs = self.btrfs_manager.clone();
                let agent_slot = self.slot_manager.clone();
                let agent_watchdog = self.watchdog_monitor.clone();
                let agent_telemetry = self.telemetry_sink.clone();
                let config = self.config.clone();

                tokio::spawn(async move {
                    let agent = MuConDeAgent {
                        config,
                        btrfs_manager: agent_btrfs,
                        slot_manager: agent_slot,
                        watchdog_monitor: agent_watchdog,
                        telemetry_sink: agent_telemetry,
                    };
                    if let Err(e) = agent.handle_connection(stream).await {
                        tracing::error!("Connection error: {}", e);
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btrfs::MockCommandRunner;
    use crate::watchdog::MockHealthProber;
    use muconde_ipc::{
        ArtifactTaintNotification, DeploymentSlot, HealthProbeTelemetry, IntegrationTestReport,
        StageDeploymentResponse,
    };
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_agent_stage_deployment_request_over_duplex() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        fs::create_dir_all(&root).unwrap();

        let runner = Arc::new(MockCommandRunner::new(true));
        let prober = Arc::new(MockHealthProber::new(true));

        let config = MuConDeAgentConfig {
            node_id: "node-test-1".into(),
            muconde_root: root.clone(),
            ..Default::default()
        };

        // Prepare dummy candidate binary in staging/
        let staging_dir = root.join("staging");
        fs::create_dir_all(&staging_dir).unwrap();
        let artifact_hash = "abc123456789";
        fs::write(staging_dir.join(artifact_hash), b"binary_data").unwrap();

        let agent = Arc::new(MuConDeAgent::new(config, runner, prober));

        let (mut client, server) = tokio::io::duplex(64 * 1024);

        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            agent_server.handle_connection(server).await.unwrap();
        });

        let fory = create_fory_runtime().unwrap();

        // 1. Client sends StageDeploymentRequest
        let stage_req = StageDeploymentRequest {
            deployment_id: "dep-ipc-1".into(),
            lease_id: "lease-1".into(),
            service_name: "action-runner".into(),
            artifact_sha256: artifact_hash.into(),
            target_slot: DeploymentSlot::SlotB,
        };

        let req_bytes = fory.serialize(&stage_req).unwrap();
        let req_header = IpcHeader::new(MSG_TYPE_STAGE_DEPLOY_REQ, req_bytes.len() as u32, 0, 1);
        write_frame(&mut client, &req_header, &req_bytes)
            .await
            .unwrap();

        // 2. Client receives StageDeploymentResponse
        let (resp_hdr, resp_payload) = read_frame(&mut client).await.unwrap();
        assert_eq!(resp_hdr.msg_type, MSG_TYPE_STAGE_DEPLOY_RESP);
        let resp: StageDeploymentResponse = fory.deserialize(&resp_payload).unwrap();
        assert_eq!(resp.deployment_id, "dep-ipc-1");
        assert!(resp.staged_ok);

        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    async fn test_agent_slot_swap_and_telemetry_over_duplex() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let service = "action-runner";

        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();

        let runner = Arc::new(MockCommandRunner::new(true));
        let prober = Arc::new(MockHealthProber::new(true));

        let config = MuConDeAgentConfig {
            node_id: "node-test-swap".into(),
            muconde_root: root.clone(),
            required_consecutive_successes: 2,
            ..Default::default()
        };

        let agent = Arc::new(MuConDeAgent::new(config, runner, prober));
        let (mut client, server) = tokio::io::duplex(64 * 1024);

        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            agent_server.handle_connection(server).await.unwrap();
        });

        let fory = create_fory_runtime().unwrap();

        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-swap-stream".into(),
            lease_id: "lease-stream".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "action-runner.service".into(),
            warmup_timeout_secs: 5,
        };

        let cmd_bytes = fory.serialize(&swap_cmd).unwrap();
        let cmd_header = IpcHeader::new(MSG_TYPE_SLOT_SWAP, cmd_bytes.len() as u32, 0, 100);
        write_frame(&mut client, &cmd_header, &cmd_bytes)
            .await
            .unwrap();

        // Read streamed HealthProbeTelemetry frames
        let mut telemetry_frames = 0;
        loop {
            tokio::select! {
                frame_res = read_frame(&mut client) => {
                    match frame_res {
                        Ok((hdr, payload)) => {
                            if hdr.msg_type == MSG_TYPE_HEALTH_PROBE {
                                telemetry_frames += 1;
                                let telem: HealthProbeTelemetry = fory.deserialize(&payload).unwrap();
                                assert_eq!(telem.deployment_id, "dep-swap-stream");
                                assert!(telem.systemd_active);
                                if telemetry_frames >= 2 {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(3)) => break,
            }
        }

        assert!(telemetry_frames >= 2);
        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    async fn test_agent_heartbeat_over_duplex() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");

        let runner = Arc::new(MockCommandRunner::new(true));
        let prober = Arc::new(MockHealthProber::new(true));

        let config = MuConDeAgentConfig {
            node_id: "node-heartbeat".into(),
            muconde_root: root,
            ..Default::default()
        };

        let agent = Arc::new(MuConDeAgent::new(config, runner, prober));
        let (mut client, server) = tokio::io::duplex(64 * 1024);

        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            agent_server.handle_connection(server).await.unwrap();
        });

        let fory = create_fory_runtime().unwrap();

        let hb = HeartbeatTelemetry {
            node_id: "node-heartbeat".into(),
            active_deployments: 0,
            btrfs_free_bytes: 50 * 1024 * 1024 * 1024,
            timestamp_epoch_ms: 12345678,
        };

        let hb_bytes = fory.serialize(&hb).unwrap();
        let hb_header = IpcHeader::new(MSG_TYPE_HEARTBEAT, hb_bytes.len() as u32, 0, 200);
        write_frame(&mut client, &hb_header, &hb_bytes)
            .await
            .unwrap();

        let (resp_hdr, resp_payload) = read_frame(&mut client).await.unwrap();
        assert_eq!(resp_hdr.msg_type, MSG_TYPE_HEARTBEAT);
        let resp_hb: HeartbeatTelemetry = fory.deserialize(&resp_payload).unwrap();
        assert_eq!(resp_hb.node_id, "node-heartbeat");

        drop(client);
        let _ = agent_task.await;
    }

    #[test]
    fn test_build_tls_server_config() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let temp = tempdir().unwrap();

        // 1. Generate CA
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let ca_cert_path = temp.path().join("ca.crt");
        fs::write(&ca_cert_path, ca_cert.pem()).unwrap();

        // 2. Generate Server Certificate
        let server_key = KeyPair::generate().unwrap();
        let server_params = CertificateParams::new(vec!["node-a".to_string()]).unwrap();
        let server_cert = server_params.self_signed(&server_key).unwrap();

        let server_cert_path = temp.path().join("server.crt");
        let server_key_path = temp.path().join("server.key");
        fs::write(&server_cert_path, server_cert.pem()).unwrap();
        fs::write(&server_key_path, server_key.serialize_pem()).unwrap();

        // 3. Verify server config builds cleanly
        let config = build_tls_server_config(&ca_cert_path, &server_cert_path, &server_key_path);
        assert!(config.is_ok());

        // Error path: non-existent file
        let invalid =
            build_tls_server_config("nonexistent.crt", &server_cert_path, &server_key_path);
        assert!(invalid.is_err());
    }

    #[tokio::test]
    async fn test_agent_rollback_command_over_duplex() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let service = "muregist";

        // Setup physical slots
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();

        let runner = Arc::new(MockCommandRunner::new(true));
        let prober = Arc::new(MockHealthProber::new(true));

        let config = MuConDeAgentConfig {
            node_id: "node-test-rb".into(),
            muconde_root: root.clone(),
            ..Default::default()
        };

        let agent = Arc::new(MuConDeAgent::new(config, runner, prober));
        // Start on Slot B
        agent
            .slot_manager
            .atomic_swap_active_slot(service, Slot::B)
            .unwrap();

        let (mut client, server) = tokio::io::duplex(64 * 1024);

        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            agent_server.handle_connection(server).await.unwrap();
        });

        let fory = create_fory_runtime().unwrap();

        // Send RollbackCommand
        let rollback_cmd = RollbackCommand {
            deployment_id: "dep-abort-1".into(),
            lease_id: "lease-abort".into(),
            service_name: service.into(),
            restore_slot: DeploymentSlot::SlotA,
            failed_artifact_sha256: "bad-sha".into(),
            reason: "Controller commanded emergency rollback".into(),
        };

        let cmd_bytes = fory.serialize(&rollback_cmd).unwrap();
        let cmd_header = IpcHeader::new(MSG_TYPE_ROLLBACK, cmd_bytes.len() as u32, 0, 42);
        write_frame(&mut client, &cmd_header, &cmd_bytes)
            .await
            .unwrap();

        // Expect IntegrationTestReport
        let (rep_hdr, rep_payload) = read_frame(&mut client).await.unwrap();
        assert_eq!(rep_hdr.msg_type, MSG_TYPE_IT_REPORT);
        let report: IntegrationTestReport = fory.deserialize(&rep_payload).unwrap();
        assert_eq!(report.deployment_id, "dep-abort-1");
        assert!(!report.passed);

        // Expect ArtifactTaintNotification
        let (taint_hdr, taint_payload) = read_frame(&mut client).await.unwrap();
        assert_eq!(taint_hdr.msg_type, MSG_TYPE_ARTIFACT_TAINT);
        let taint: ArtifactTaintNotification = fory.deserialize(&taint_payload).unwrap();
        assert_eq!(taint.deployment_id, "dep-abort-1");
        assert!(taint.rollback_completed);

        // Verify active slot is reverted to A
        assert_eq!(
            agent.slot_manager.read_active_slot(service).unwrap(),
            Some(Slot::A)
        );

        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    async fn test_agent_emits_otel_spans_and_metrics_for_staging_swap_probes_and_rollback() {
        use crate::telemetry::RecordingTelemetrySink;

        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let service = "action-runner";

        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();

        let staging_dir = root.join("staging");
        fs::create_dir_all(&staging_dir).unwrap();
        let artifact_hash = "sha256-candidate-otel";
        fs::write(staging_dir.join(artifact_hash), b"candidate_binary").unwrap();

        let runner = Arc::new(MockCommandRunner::new(true));
        let prober = Arc::new(MockHealthProber::new(true));
        let recorder = Arc::new(RecordingTelemetrySink::new());

        let config = MuConDeAgentConfig {
            node_id: "worker-riscv64".into(),
            muconde_root: root.clone(),
            required_consecutive_successes: 2,
            ..Default::default()
        };

        let agent = Arc::new(
            MuConDeAgent::new(config, runner, prober).with_telemetry_sink(recorder.clone()),
        );
        let (mut client, server) = tokio::io::duplex(64 * 1024);

        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            agent_server.handle_connection(server).await.unwrap();
        });

        let fory = create_fory_runtime().unwrap();

        // 1. StageDeployment
        let stage_req = StageDeploymentRequest {
            deployment_id: "dep-otel-1".into(),
            lease_id: "lease-otel-1".into(),
            service_name: service.into(),
            artifact_sha256: artifact_hash.into(),
            target_slot: DeploymentSlot::SlotB,
        };
        let req_bytes = fory.serialize(&stage_req).unwrap();
        let req_header = IpcHeader::new(MSG_TYPE_STAGE_DEPLOY_REQ, req_bytes.len() as u32, 0, 1);
        write_frame(&mut client, &req_header, &req_bytes)
            .await
            .unwrap();
        let (_resp_hdr, _resp_payload) = read_frame(&mut client).await.unwrap();

        // 2. SlotSwap + Health Probes
        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-otel-1".into(),
            lease_id: "lease-otel-1".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "action-runner.service".into(),
            warmup_timeout_secs: 5,
        };
        let swap_bytes = fory.serialize(&swap_cmd).unwrap();
        let swap_header = IpcHeader::new(MSG_TYPE_SLOT_SWAP, swap_bytes.len() as u32, 0, 2);
        write_frame(&mut client, &swap_header, &swap_bytes)
            .await
            .unwrap();

        let mut probes_received = 0;
        while probes_received < 2 {
            let (hdr, _payload) = read_frame(&mut client).await.unwrap();
            if hdr.msg_type == MSG_TYPE_HEALTH_PROBE {
                probes_received += 1;
            }
        }

        // 3. RollbackCommand
        let rollback_cmd = RollbackCommand {
            deployment_id: "dep-otel-1".into(),
            lease_id: "lease-otel-1".into(),
            service_name: service.into(),
            restore_slot: DeploymentSlot::SlotA,
            failed_artifact_sha256: artifact_hash.into(),
            reason: "SLO latency breach".into(),
        };
        let rb_bytes = fory.serialize(&rollback_cmd).unwrap();
        let rb_header = IpcHeader::new(MSG_TYPE_ROLLBACK, rb_bytes.len() as u32, 0, 3);
        write_frame(&mut client, &rb_header, &rb_bytes)
            .await
            .unwrap();
        let _ = read_frame(&mut client).await.unwrap();
        let _ = read_frame(&mut client).await.unwrap();

        drop(client);
        let _ = agent_task.await;

        let spans = recorder.recorded_spans().await;
        let span_names: Vec<&str> = spans.iter().map(|s| s.span_name.as_str()).collect();
        assert!(span_names.contains(&"muconde.agent.stage_deployment"));
        assert!(span_names.contains(&"muconde.agent.slot_swap"));
        assert!(span_names.contains(&"muconde.agent.rollback"));

        let metrics = recorder.recorded_metrics().await;
        let metric_names: Vec<&str> = metrics.iter().map(|m| m.metric_name.as_str()).collect();
        assert!(metric_names.contains(&"muconde.agent.stage_duration_ms"));
        assert!(metric_names.contains(&"muconde.agent.active_slot"));
        assert!(metric_names.contains(&"muconde.agent.slot_probe_latency_ms"));
        assert!(metric_names.contains(&"muconde.agent.slot_probe_healthy"));
        assert!(metric_names.contains(&"muconde.agent.rollback_duration_ms"));
    }
}
