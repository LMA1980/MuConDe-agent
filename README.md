# MuConDe-agent

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs">
    <img src="https://hook.lma1980.duckdns.org/cards/LMA1980/MuConDe-agent/card.svg" alt="MuConDe-agent Factory Scorecard" width="520"/>
  </a>
</p>

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/MuConDe-agent/status.svg" alt="CI Status"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/MuConDe-agent/score.svg" alt="Quality Score"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/MuConDe-agent/coverage.svg" alt="Coverage"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/MuConDe-agent/benchmark.svg" alt="Benchmark"/></a>
</p>

---

Node-level continuous delivery daemon executing atomic filesystem operations, dual A/B root subvolume switching, health probes, and autonomous watchdog rollbacks.

Resident systemd daemon operating natively across heterogeneous cluster nodes: SpacemiT K3 RISC-V (`pey-wail-deu`), Intel N100 (`entrance`), and Intel Xeon (`rubicon`).

---

## Core Capabilities

- **Dual A/B Btrfs Root Slots**:
  - Maintains dual root subvolume slots (`@root_a` for active production, `@root_b` for canary staging).
  - Isolates ephemeral staging state with shared persistent data (`@data`, `@logs`).
- **Atomic Subvolume Snapshots**:
  - Uses instantaneous Btrfs CoW snapshots (`btrfs subvolume snapshot`).
  - Creates pre-deployment rollback anchor snapshots prior to stage mutation.
- **Local Health Probes & Watchdogs**:
  - Executes local HTTP, TCP, and systemd unit readiness probes against the staged service in Slot B.
  - Streams real-time probe telemetry to `MuConDe-controller` over `MuConDe-ipc`.
- **Autonomous Rollback Watchdog**:
  - Enforces local hardware and software lease watchdogs.
  - If controller heartbeat or lease renewal drops during an in-flight deployment, the agent autonomously reverts the active subvolume and restarts production services in < 1 second.

---

## Btrfs Subvolume Topology

```text
/dev/nvme0n1p2 (Btrfs Pool)
├── @root_a          (Active Slot A - mounted at /)
├── @root_b          (Staging Slot B - mounted at /mnt/slot_b during canary)
├── @snapshots/      (Pre-deployment anchor snapshots: @root_a_snap_<timestamp>)
├── @data            (Shared persistent application state)
└── @logs            (Unified systemd and audit journals)
```

---

## Autonomous Rollback Automata

```text
[ Controller Commands ] ──> Lease (TTL: 300s)
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
       [ Health Probes Pass ]          [ Health Probe Fail OR Lease Expired ]
               │                               │
               ▼                               ▼
     Atomic Promotion Swap           Autonomous Btrfs Snapshot Rollback
  (@root_b promoted to active)      (Revert to @root_a_snap_<timestamp>)
```

---

## Operational Invariants

1. **Non-Destructive Rollback**: Rollback operations restore exact verified Btrfs snapshots; never perform blind directory deletions or partial cleanup.
2. **Atomic Binary Installation**: Daemon and service binary updates strictly use `install -m 755` rather than `cp` to avoid `ETXTBSY` (Text file busy) execution errors.
3. **Fail-Closed Watchdog**: In the event of network partition during active staging, the local agent defaults to rolling back Slot B rather than leaving unverified services running.

---

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only). See LICENSE for details.
