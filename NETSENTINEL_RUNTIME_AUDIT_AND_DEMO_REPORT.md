# NetSentinel Runtime Audit and Demo Readiness

## Scope and baseline

Audit baseline: branch `main`, commit `966d45ca761e2a4aedf9a37f7047fb2aff9df992` (matched `origin/main`). The working tree also contained an untracked `AGENTS.md`; it was preserved and is not included in the code commit.

The repository and implementation were reviewed across the packet detector, ML scoring and persistence, risk engine, firewall, host/SSH monitor, incident manager, APIs, dashboard data consumers, and existing tests. The local backend and frontend were not running during this audit: port 5000 refused connections and no app processes were present. As a result, live dashboard and seven-scenario end-to-end verification could not be performed.

## Root-cause findings and corrections

### Port scan target attribution

`TrafficDetector.detect_port_scan()` keyed its rolling probe queue only by source IP. Probes against different destination hosts (and TCP/UDP) could combine to reach the threshold, while the emitted event attributed the scan to only the latest packet's destination. The state is now keyed by `(source_ip, destination_ip, protocol)`, and cooldowns are scoped to that scan target/protocol. Event evidence includes destination, protocol, threshold, window, unique port count, and sampled ports. Regression tests cover multi-target negative control and event attribution.

### Unattributed risk assessments

`RiskEngine.assess_rule_event()` and `assess()` replaced missing source addresses with `127.0.0.1`. This made unrelated events share repeat-frequency and cross-domain correlation state under a false source identity. Assessments now preserve `source_ip=None` and skip source-based repeat/correlation boosts when no source is known. The existing database column is non-nullable, so persistence uses the explicit `UNATTRIBUTED` marker; this is not treated as an address or used for correlation. A regression test verifies the in-memory risk state remains empty and the marker persists.

### ML-only incident creation

The application callback sent every ML anomaly directly to incident correlation, even though the ML observation is persisted independently and may not have corroborating evidence. The callback now retains ML events and risk assessments without creating a standalone incident. This preserves ML evidence for analysis while requiring independent rule evidence to open an incident. Existing incident-manager behavior for explicit event correlation remains unchanged.

### SSH log source

The host had no `/var/log/auth.log` or `/var/log/secure`; SSH is active and journald is available. SSH log reading now falls back to `journalctl` for `ssh.service` and `sshd.service`, tracking new messages via journal cursor. Existing file reading remains preferred, and explicit `NETSENTINEL_SSH_LOG_PATH` continues to select a file. A mocked journal-reader regression test was added. A live failed-login event was not generated during this audit.

### ML artifact and restart warm-up

The existing local metadata at `data/models/model_metadata.json` reports `training_sample_count: 10`, while the approved runtime minimum is 512. Direct load verification failed closed with: `Insufficient baseline samples in persisted model: found 10, minimum required is 512.` This explains why startup does not reuse this artifact and resumes collection. The model artifact and metadata were inspected but not modified or deleted. A fresh, valid 512-window model must be trained and saved before restart can remain READY.

### Firewall configuration

The repository `.env` currently sets `NETSENTINEL_FIREWALL_ENABLED=true`, `NETSENTINEL_AUTO_BLOCK=true`, and `NETSENTINEL_FIREWALL_DRY_RUN=false`. These settings are not safe defaults and conflict with a dry-run demonstration expectation. I did not change the user's `.env` or execute any firewall operation. This audit's automated suite explicitly overrode the settings to disable real firewall execution.

Use explicit safe overrides when starting a demonstration backend:

```bash
NETSENTINEL_FIREWALL_ENABLED=false \
NETSENTINEL_AUTO_BLOCK=false \
NETSENTINEL_FIREWALL_DRY_RUN=true \
.venv/bin/python backend/app.py
```

The environment overrides take precedence over `.env`. Real blocking was not attempted. It must be verified only against an authorized isolated target with an explicit rollback procedure; a scanner on the same host may be rejected by local-interface protection.

## Detection and dashboard findings

- ML-only risk is bounded to `0.35 × anomaly_score` before other modifiers. Rule, repeat, correlation, and threat-intelligence modifiers remain visible in assessment evidence.
- The ML event callback now avoids standalone incident creation; raw ML anomaly events remain persisted and broadcast.
- `query_security_summary` reports historical event and incident counts, while `/api/risk/stats` is in-memory runtime state. They are not equivalent measures or necessarily the same time range. The Detection page uses both for separate chart data; live cross-page/dashboard consistency was not verified because services were unavailable.
- The Detection page's two distribution charts now use the same 24-hour event summary; the second chart is labeled Security Event Severity, not composite risk-assessment severity. Historical runtime status remains unverified.
- Detection vectors count persisted security events; incident counts count correlated incidents. They should not be interpreted as the same quantity.
- Dashboard charts, Socket.IO freshness, firewall kernel state, and historical-vs-session presentation remain NOT VERIFIED at runtime.

## Verification results

- Final full backend suite: **465 passed** with isolated SQLite and firewall explicitly disabled/dry-run enabled.
- Targeted detector, risk, SSH, database, network E2E, and validation-harness tests: **49 passed** after correcting issues found by the suite.
- ML end-to-end, diagnostics, and production-baseline tests: **24 passed** with safe firewall overrides.
- Frontend production build: **passed** (`vite build`, 2363 modules transformed).
- SSH journal smoke check: reader reported `RUNNING`, source `journald`, and returned no new messages. This confirmed the configured source is readable in this workspace, not receipt of an SSH failure event. A permission-warning regression test verifies hidden journal access is reported as `PERMISSION_DENIED`.
- Model reload: **failed closed as expected** because the persisted artifact has 10 rather than 512 training samples.
- Runtime API contract against a running server, browser console/network, live firewall integration, database persistence from a running service, and seven full dashboard attack scenarios: **NOT VERIFIED**.

## Seven-scenario demonstration matrix

The repository contains deterministic unit/integration fixtures for each detector family, but the complete live pipeline through a running backend, database, and dashboard was not available in this environment. Therefore none is claimed as end-to-end passed.

| Scenario | Automated fixture coverage | Live detector → event → persistence → dashboard | Result |
|---|---|---|---|
| Port scan | Rule detector and network E2E tests; new target-isolation tests | Not run | NOT VERIFIED end-to-end |
| SYN flood-like burst | Rule detector and network E2E tests | Not run | NOT VERIFIED end-to-end |
| Unusual traffic / Isolation Forest | ML pipeline and baseline tests | Not run; current artifact is incompatible | NOT VERIFIED end-to-end |
| ARP spoofing indicators | ARP detector and host/network E2E tests | Not run | NOT VERIFIED end-to-end |
| ICMP sweep | ICMP detector and network E2E tests | Not run | NOT VERIFIED end-to-end |
| SSH login failures | SSH parser/reader tests; journald source smoke check | No new auth failure was generated | NOT VERIFIED end-to-end |
| File modification | FIM scanner, database, and host-security tests | Not run | NOT VERIFIED end-to-end |

## Remaining work before claiming demo readiness

1. Train a genuine 512-window benign baseline using the approved 5-second / 13-feature / Isolation Forest configuration; verify artifact metadata and reload after backend restart. Do not use the current 10-window artifact as the production baseline.
2. Start backend with the safe firewall overrides above and start the frontend. Verify `/api/host/status`, a controlled local SSH failure, event persistence, and Host Security display.
3. Run the seven positive/negative scenarios only with synthetic fixtures or an isolated lab; verify attribution, persistence, incidents, dashboard, and firewall result for each.
4. Decide whether the user's current `.env` firewall settings are intentional. Keep real blocking disabled unless testing in an isolated lab.
5. Reconcile charts with explicit metric labels and a consistent selected time range, then inspect browser network/console state.

## Final state

Implementation changes and regression tests were verified with 465 passing backend tests and a successful production frontend build. The untracked `AGENTS.md` remains untouched. The repository is not declared demonstration-ready because live runtime and all seven end-to-end scenarios remain unverified.
