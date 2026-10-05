# NetSentinel – Hybrid Network and Host Intrusion Detection and Prevention System

## 1. Project Description
**NetSentinel** is a modern Linux-based hybrid Network Intrusion Detection System (NIDS), Host Intrusion Detection System (HIDS), and Intrusion Prevention System (IPS). It captures and analyzes raw network traffic, applies signature and rule-based detection alongside machine learning anomaly detection (Isolation Forest), evaluates composite security risk levels, and mitigates threats safely using Linux `iptables` firewall rules on an isolated managed chain.

> **Implementation Status (Phase 6 Completed):** NetSentinel includes live network packet capture using Linux `AF_PACKET` raw sockets, a complete packet parser, real-time traffic rate metrics, a stateful **Rule-Based Intrusion Detection Engine** (`detector.py`), an unsupervised **Machine Learning Anomaly Detection System** (`backend/ml/`) powered by Scikit-learn's `IsolationForest`, a deterministic **Composite Risk Engine** (`risk_engine.py`), a safe **Linux iptables Firewall Manager** (`firewall.py`), a background **Host Telemetry Worker** (`telemetry.py`), and **Durable Security History Persistence & Reporting** (`database.py`). All security incidents, assessments, firewall mitigations, and host telemetry snapshots are durably stored in SQLite with bounded querying and automated retention pruning.

---

## 2. Technology Stack

### Backend
* **Python 3**
* **Linux `AF_PACKET` Raw Sockets** - Kernel-level raw Ethernet frame capture
* **Linux `iptables`** - Packet filtering and mitigation via dedicated `NETSENTINEL` chain
* **Scikit-learn** - Unsupervised `IsolationForest` anomaly detection
* **NumPy & Joblib** - High-performance numerical feature arrays and model persistence
* **Flask** - REST API framework (`/api/health`, `/api/metrics`, `/api/alerts`, `/api/events`, `/api/security/summary`, `/api/telemetry/*`, `/api/ml/*`, `/api/risk/*`, `/api/firewall/*`)
* **Flask-SocketIO** - Real-time WebSocket event communication (`traffic_metrics`, `security_event`, `ml_anomaly`, `risk_assessment`, `firewall_action`, `host_telemetry`, `security_summary`)
* **Flask-SQLAlchemy / SQLAlchemy** - Database ORM & persistence models (`SecurityEventRecord`, `RiskAssessmentRecord`, `FirewallActionRecord`, `HostTelemetryRecord`)
* **SQLite** - Embedded database storage with automated time-based retention pruning
* **psutil** - Host system telemetry monitoring (CPU, RAM, disk, load average, host I/O rates)
* **pytest** - Automated test suite (79 tests)

### Frontend
* **React 18** - UI framework
* **Vite** - High-performance frontend build tool & proxy server
* **JavaScript (ES6+ / JSX)** - Core frontend scripting
* **Recharts** - Real-time traffic rate, anomaly score trend, and CPU/RAM resource trend charts
* **Lucide React** - Modern SOC-style UI iconography

---

## 3. Directory Structure

```
NetSentinel/
│
├── backend/
│   ├── app.py           # Flask app factory, API routes, Socket.IO & capture lifecycle
│   ├── config.py        # Centralized settings, network interface, detection thresholds, telemetry & retention config
│   ├── capture.py       # AF_PACKET raw socket capture engine & rolling metrics aggregator
│   ├── parser.py        # Complete Ethernet, IPv4, IPv6, TCP, UDP, ICMP packet parser
│   ├── detector.py      # Rule-based intrusion detection engine & state manager
│   ├── ml/              # Machine Learning Anomaly Detection Package (Phase 4)
│   │   ├── __init__.py
│   │   ├── feature_extractor.py # 13 numerical window traffic features & TrafficWindow buffer
│   │   ├── model.py             # IsolationForestModel lifecycle, training, scoring & persistence
│   │   └── detector.py          # MLAnomalyDetector coordinator, baseline collection, cooldown & events
│   ├── risk_engine.py   # Composite Risk Engine (rule + ML evidence correlation, repeat boost)
│   ├── firewall.py      # Linux iptables firewall manager (dedicated chain, safeguards, expiration)
│   ├── database.py      # SQLAlchemy persistence models, historical query APIs, and retention pruning
│   └── telemetry.py     # Background psutil host telemetry worker, rate math, and lifecycle
│
├── frontend/
│   ├── src/
│   │   ├── components/  # Modular UI components (Header, DashboardCard, etc.)
│   │   ├── pages/       # Dashboard view (Live alerts, ML telemetry, Risk, Firewall, System Resources & History)
│   │   ├── services/    # REST API & Socket.IO client connections (Events, History, Telemetry, Risk & Firewall)
│   │   ├── App.jsx      # Root application component with live state sync
│   │   ├── App.css      # SOC dark theme styling with resource gauges & history activity table
│   │   └── main.jsx     # React entry point
│   ├── index.html       # HTML entry point
│   ├── package.json     # Node dependencies and scripts
│   └── vite.config.js   # Vite server setup & backend API proxy configuration
│
├── data/
│   ├── models/          # Persisted Isolation Forest models and metadata (.joblib, .json)
│   └── netsentinel.db   # SQLite database storage
├── tests/               # Automated unit and integration tests (79 tests)
│   ├── test_health.py   # Test GET /api/health
│   ├── test_parser.py   # Parser unit tests with binary packet fixtures
│   ├── test_capture.py  # Traffic metrics & capture lifecycle tests
│   ├── test_detector.py # Rule detection, cooldown, state cleanup, and alerts tests
│   ├── test_ml.py       # ML feature extraction, model lifecycle, baseline collection & anomaly detection tests
│   ├── test_risk.py     # Composite risk scoring, repeat frequency, clamping & boundary tests
│   ├── test_firewall.py # IP validation, safety safeguards, dedicated chain & expiration tests
│   ├── test_database.py # Database persistence models, filtering, pagination, and retention cleanup tests
│   ├── test_telemetry.py# Host telemetry sampling, rate delta math, and worker lifecycle tests
│   ├── test_history_api.py # Historical REST APIs, summary aggregates, and pipeline persistence tests
│   ├── test_risk_firewall_api.py # Risk and firewall REST APIs and Socket.IO tests
│   └── test_socket.py   # Test Socket.IO connection and ping
├── requirements.txt     # Python backend dependencies
├── .gitignore           # Git ignore configurations
└── README.md            # Project documentation
```

---

## 4. Detection & Mitigation Pipeline

```text
Linux Network Interface (e.g., enp0s3)
                 ↓
       AF_PACKET Raw Socket
                 ↓
      backend/capture.py (Capture Loop)
                 ↓
      backend/parser.py (Structured ParsedPacket)
                 ↓
       Packet Callback Dispatcher
       ┌─────────┴────────────────────────┐
       ↓                                  ↓
backend/detector.py              backend/ml/detector.py
(Rule-Based Engine)              (ML Anomaly Detector)
  ├── Port Scan Rule               ├── TrafficWindow Buffer (e.g., 5s)
  ├── SYN Flood Rule               ├── FeatureExtractor (13 features)
  ├── NULL Scan Rule               ├── Baseline Profile Collection
  └── XMAS Scan Rule               └── IsolationForest Inference
       ↓                                  ↓
Structured SecurityEvent         Structured MLAnomalyEvent
       │                                  │
       └──────────────┬───────────────────┘
                      ↓
          backend/risk_engine.py
         (Composite Risk Engine)
                      ↓
           RiskAssessment Object
    (Score: 0.0 - 1.0, Action: block/alert/log/monitor)
                      ↓
           backend/firewall.py
        (Linux iptables Manager)
      [Dedicated Chain: NETSENTINEL]
                      ↓
  ┌───────────────────┴───────────────────┐
  ↓                                       ↓
SQLite Database                  Flask-SocketIO & REST APIs
(RiskAssessmentRecord)           (/api/risk/*, /api/firewall/*)
                                          ↓
                             React SOC Dashboard
                  (Composite Risk & Firewall Mitigation Cards)
```

---

## 5. Composite Risk Engine

The Risk Engine (`backend/risk_engine.py`) computes a normalized composite risk score $[0.0, 1.0]$ by synthesizing deterministic rule detections with behavioral ML anomaly scores:

### Scoring Formula
$$\text{combined\_score} = \begin{cases} 
0.65 \times \text{rule\_score} + 0.35 \times \text{ml\_anomaly\_score} & \text{if rule evidence exists} \\
0.35 \times \text{ml\_anomaly\_score} & \text{if ML anomaly only}
\end{cases}$$

* **Rule Severity Scores**:
  * `LOW` = $0.20$
  * `MEDIUM` = $0.40$
  * `HIGH` = $0.70$
  * `CRITICAL` = $0.90$
* **Repeated Detection Frequency Boost**: Each additional detection from the same source IP within a sliding 60-second window increments the base rule score by $+0.05$ (up to a bounded maximum boost of $+0.20$).
* **ML Isolation**: Because ML anomaly alone is weighted at $0.35$, an ML anomaly by itself can never exceed $0.35$ (MEDIUM risk), mathematically preventing false-positive automatic blocks without rule corroboration.
* **Score Clamping**: All calculated scores are strictly clamped to $[0.0, 1.0]$.

### Risk Levels & Recommended Actions

| Score Range | Risk Level | Recommended Action | Operational Meaning |
|---|---|---|---|
| `0.00 – 0.29` | **`LOW`** | `monitor` | Normal/benign traffic; observation only |
| `0.30 – 0.59` | **`MEDIUM`** | `log` | Minor anomaly or single low-severity probe; logged |
| `0.60 – 0.79` | **`HIGH`** | `alert` | High-confidence intrusion attempt; active SOC alert |
| `0.80 – 1.00` | **`CRITICAL`** | `block` | Severe attack pattern; candidate for automated blocking |

---

## 6. Linux iptables Firewall Mitigation

NetSentinel implements safe, reversible packet filtering using Linux `iptables`.

### Dedicated Managed Chain (`NETSENTINEL`)
* All managed rules are placed in an isolated chain: `NETSENTINEL`.
* The chain is inserted at position 1 of the `INPUT` chain:
  `iptables -I INPUT 1 -j NETSENTINEL`
* Blocking an IP inserts a drop rule:
  `iptables -I NETSENTINEL 1 -s <IP> -j DROP`
* Global chains (`INPUT`, `FORWARD`, `OUTPUT`) are **NEVER** flushed.
* Clearing managed rules flushes only the dedicated chain:
  `iptables -F NETSENTINEL`

### Safety Safeguards
The firewall manager verifies each IP against strict safety criteria before blocking:
1. **Loopback Protection**: `127.0.0.0/8` and `::1` are strictly unblockable.
2. **Local Machine Interface Protection**: Discovers all local host IP addresses (via `psutil.net_if_addrs()`) and prevents host self-isolation.
3. **Multicast & Unspecified**: `224.0.0.0/4`, `ff00::/8`, `0.0.0.0`, and `::` are rejected.
4. **Broadcast Protection**: Global broadcast `255.255.255.255` is rejected.
5. **Operator Allowlist**: Configurable trusted IPs and CIDR subnets (`NETSENTINEL_FIREWALL_ALLOWLIST`).
6. **Command Injection Prevention**: Executed strictly via argument arrays (`subprocess.run(["iptables", ...])`) without `shell=True`.

### Temporary Block Expiration
* IP blocks are temporary by default (`NETSENTINEL_BLOCK_DURATION`, default: 300 seconds / 5 minutes).
* Active blocks are automatically unblocked upon expiration.
* Duplicate blocks update the existing expiration timestamp rather than adding duplicate kernel rules.

### Safe Default Behavior
* **Firewall Disabled by Default**: `NETSENTINEL_FIREWALL_ENABLED=false` and `NETSENTINEL_AUTO_BLOCK=false`.
* If disabled or in dry-run mode, risk assessments still compute recommended actions, and firewall actions are simulated in memory without invoking `iptables`.

---

## 7. How to Inspect & Manage Firewall Rules

### Inspect Active NetSentinel Rules
```bash
sudo iptables -L NETSENTINEL -v -n --line-numbers
```

### Safely Flush NetSentinel Managed Rules (Without Touching System Rules)
```bash
sudo iptables -F NETSENTINEL
```

### Remove the NetSentinel Jump from INPUT
```bash
sudo iptables -D INPUT -j NETSENTINEL
sudo iptables -X NETSENTINEL
```

---

## 8. Configuration & Environment Variables

| Variable | Default Value | Description |
|---|---|---|
| `NETSENTINEL_FIREWALL_ENABLED` | `false` | Enable/disable real Linux iptables execution |
| `NETSENTINEL_AUTO_BLOCK` | `false` | Enable/disable automated blocking on CRITICAL risk |
| `NETSENTINEL_FIREWALL_DRY_RUN` | `true` | When true, simulates firewall actions without running iptables |
| `NETSENTINEL_IPTABLES_CHAIN` | `NETSENTINEL` | Name of the dedicated iptables managed chain |
| `NETSENTINEL_BLOCK_DURATION` | `300.0` | Default temporary block duration in seconds (5 min) |
| `NETSENTINEL_MAX_BLOCKED_IPS` | `500` | Upper bound on concurrently managed blocked IPs |
| `NETSENTINEL_FIREWALL_ALLOWLIST`| `127.0.0.1,::1` | Comma-separated list of unblockable IPs or CIDRs |
| `RISK_RULE_WEIGHT` | `0.65` | Weight for rule detector evidence in composite score |
| `RISK_ML_WEIGHT` | `0.35` | Weight for ML anomaly score in composite score |
| `RISK_REPEAT_INCREMENT` | `0.05` | Score boost per repeated detection from same IP |
| `RISK_MAX_REPEAT_BOOST` | `0.20` | Maximum cumulative repeat detection boost |
| `RISK_HISTORY_WINDOW_SEC` | `60.0` | Time window for tracking repeated source IP detections |
| `RISK_AUTO_BLOCK_THRESHOLD`| `0.80` | Composite risk score threshold required for auto-block |

---

## 9. REST API & Socket.IO Endpoints

### REST API Endpoints
* `GET /api/health`: Health status.
* `GET /api/metrics`: Live packet capture and protocol statistics.
* `GET /api/alerts`: Recent rule-based security events (newest first).
* `GET /api/events`: Persisted historical security events with filtering (`since`, `until`, `source_ip`, `detection_type`, `severity`) and pagination (`limit`, `offset`).
* `GET /api/security/summary`: Aggregate security event metrics, severity breakdown, top source IPs, and risk averages.
* `GET /api/telemetry/current`: Real-time host system resource snapshot (CPU %, RAM %, disk %, OS load, host network rates).
* `GET /api/telemetry/history`: Bounded historical host telemetry for dashboard trend charts.
* `GET /api/ml/status`: Isolation Forest model lifecycle and baseline status.
* `GET /api/ml/metrics`: ML window history and recent anomaly events.
* `GET /api/risk/recent`: Recent composite risk assessments.
* `GET /api/risk/history`: Persisted historical risk assessments with filters.
* `GET /api/risk/stats`: Aggregate risk level breakdown and score averages.
* `GET /api/firewall/status`: Firewall operational mode, chain, and configuration.
* `GET /api/firewall/blocked`: List of actively blocked IPs with reasons and expiration timestamps.
* `POST /api/firewall/block`: Manually block an IP (`{"ip": "...", "reason": "...", "duration": 300}`).
* `POST /api/firewall/unblock`: Manually unblock an IP (`{"ip": "..."}`).

### Socket.IO Real-Time Streams
* `traffic_metrics`: Periodic traffic rate and protocol volume.
* `security_event`: Live rule-based intrusion detection alerts.
* `ml_anomaly`: Unsupervised ML anomaly detection alerts.
* `ml_status`: ML model lifecycle state transitions.
* `risk_assessment`: Live composite risk assessments with scores and actions.
* `firewall_action`: Real-time block and unblock audit events.
* `host_telemetry`: Periodic host system resource telemetry (CPU, RAM, disk, load, rates).
* `security_summary`: Instantaneous update of aggregate security metrics.

---

## 10. Environment Setup & Execution

### Prerequisites
* Linux operating system (kernel supporting `AF_PACKET` and `iptables`)
* Python 3.10+
* Node.js v18+ & npm

### Backend Setup
1. Create and activate virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run automated tests:
   ```bash
   pytest tests/
   ```
4. Start backend server:
   ```bash
   # Unprivileged / dry-run mode:
   python backend/app.py

   # With elevated capabilities for live AF_PACKET & iptables:
   sudo setcap cap_net_raw,cap_net_admin+eip .venv/bin/python3
   python backend/app.py
   ```

### Frontend Setup
1. Navigate to `frontend/`:
   ```bash
   cd frontend
   npm install
   ```
2. Start Vite development server:
   ```bash
   npm run dev
   ```
3. Build production assets:
   ```bash
   npm run build
   ```

---

## 11. Automated Testing

All 79 unit and integration tests run deterministically and mock `iptables` without requiring root privileges:
```bash
pytest -v tests/
```

Test coverage:
* `tests/test_parser.py`: Binary frame parsing across Ethernet, IPv4, IPv6, TCP, UDP, ICMP.
* `tests/test_capture.py`: Raw socket lifecycle, error handling, unprivileged fallbacks, and rolling metrics.
* `tests/test_detector.py`: Port scan, SYN flood, NULL scan, XMAS scan, window expiration, alert cooldowns, and memory bounds.
* `tests/test_ml.py`: 13-feature window extraction, zero-division safety, IsolationForest lifecycle, persistence, corrupted file safety, and anomaly detection.
* `tests/test_risk.py`: Severity scores, ML weighting, score clamping, boundary mapping, repeat frequency boost, and state pruning.
* `tests/test_firewall.py`: IP validation, localhost/broadcast/multicast protection, allowlists, argument security (no shell=True), expiration, and isolated chain flushing.
* `tests/test_database.py`: SQLAlchemy persistence models, queries, filtering, pagination, and automated retention cleanup.
* `tests/test_telemetry.py`: Host telemetry sampling via `psutil`, baseline priming, delta rate calculation, and thread lifecycle.
* `tests/test_history_api.py`: Historical REST APIs (`/api/events`, `/api/risk/history`, `/api/security/summary`, `/api/telemetry/*`), and firewall action persistence.
* `tests/test_risk_firewall_api.py`: Risk and firewall REST APIs, manual block/unblock validation, and Socket.IO pipeline integration.
* `tests/test_health.py` & `tests/test_socket.py`: Health endpoint and WebSocket connection tests.

---

## 12. Current Scope Limitations & Future Roadmap

* **Phase 7 - Attack Simulation, Live Validation, and Hardening**: Live automated testing scripts, multi-vector attack simulations, end-to-end detection and mitigation verification, and system hardening.

