# NetSentinel – Hybrid Network and Host Intrusion Detection and Prevention System

## 1. Project Description
**NetSentinel** is a modern Linux-based hybrid Network Intrusion Detection System (NIDS), Host Intrusion Detection System (HIDS), and Intrusion Prevention System (IPS). It captures and analyzes raw network traffic, applies signature and rule-based detection alongside machine learning anomaly detection (Isolation Forest), evaluates security risk levels, and automatically mitigates threats using Linux `iptables` firewall rules.

> **Implementation Status (Phase 4 Completed):** NetSentinel includes live network packet capture using Linux `AF_PACKET` raw sockets, a complete packet parser, real-time traffic rate metrics, a stateful **Rule-Based Intrusion Detection Engine** (`detector.py`), and an unsupervised **Machine Learning Anomaly Detection System** (`backend/ml/`) powered by Scikit-learn's `IsolationForest`. The ML system learns baseline profiles from normal traffic windows, identifies significant behavioral deviations without classifying attack signatures, and streams `ml_anomaly` events to the React dashboard. Automated firewall blocking and threat intelligence are reserved for subsequent phases.

---

## 2. Technology Stack

### Backend
* **Python 3**
* **Linux `AF_PACKET` Raw Sockets** - Kernel-level raw Ethernet frame capture
* **Scikit-learn** - Unsupervised `IsolationForest` anomaly detection
* **NumPy & Joblib** - High-performance numerical feature arrays and model persistence
* **Flask** - REST API framework (`/api/health`, `/api/metrics`, `/api/alerts`, `/api/ml/status`, `/api/ml/metrics`)
* **Flask-SocketIO** - Real-time WebSocket event communication (`traffic_metrics`, `security_event`, `ml_anomaly`, `ml_status`)
* **Flask-SQLAlchemy / SQLAlchemy** - Database ORM
* **SQLite** - Embedded event & telemetry persistence foundation
* **psutil** - System telemetry monitoring
* **pytest** - Automated test suite (41 tests)

### Frontend
* **React 18** - UI framework
* **Vite** - High-performance frontend build tool & proxy server
* **JavaScript (ES6+ / JSX)** - Core frontend scripting
* **Recharts** - Real-time traffic rate and anomaly score trend visualization charts
* **Lucide React** - Modern SOC-style UI iconography

---

## 3. Directory Structure

```
NetSentinel/
│
├── backend/
│   ├── app.py           # Flask app factory, API routes, Socket.IO & capture lifecycle
│   ├── config.py        # Centralized settings, network interface selection, detection thresholds & ML configuration
│   ├── capture.py       # AF_PACKET raw socket capture engine & rolling metrics aggregator
│   ├── parser.py        # Complete Ethernet, IPv4, IPv6, TCP, UDP, ICMP packet parser
│   ├── detector.py      # Rule-based intrusion detection engine & state manager
│   ├── ml/              # Machine Learning Anomaly Detection Package (Phase 4)
│   │   ├── __init__.py
│   │   ├── feature_extractor.py # 13 numerical window traffic features & TrafficWindow buffer
│   │   ├── model.py             # IsolationForestModel lifecycle, training, scoring & persistence
│   │   └── detector.py          # MLAnomalyDetector coordinator, baseline collection, cooldown & events
│   ├── risk_engine.py   # Composite threat risk evaluation skeleton (Phase 5)
│   ├── firewall.py      # Linux iptables firewall manager skeleton (Phase 5)
│   ├── database.py      # SQLAlchemy database configuration and model base
│   └── telemetry.py     # System telemetry & resource monitor module
│
├── frontend/
│   ├── src/
│   │   ├── components/  # Modular UI components (Header, DashboardCard, etc.)
│   │   ├── pages/       # Page views (Dashboard with live alerts, ML anomaly telemetry & charts)
│   │   ├── services/    # REST API & Socket.IO client connections (extended with ML endpoints)
│   │   ├── App.jsx      # Root application component
│   │   ├── App.css      # SOC dark theme styling with ML progress bar & badges
│   │   └── main.jsx     # React entry point
│   ├── index.html       # HTML entry point
│   ├── package.json     # Node dependencies and scripts
│   └── vite.config.js   # Vite server setup & backend API proxy configuration
│
├── data/
│   ├── models/          # Persisted Isolation Forest models and metadata (.joblib, .json)
│   └── netsentinel.db   # SQLite database storage
├── tests/               # Automated unit tests (41 tests)
│   ├── test_health.py   # Test GET /api/health
│   ├── test_parser.py   # Parser unit tests with binary packet fixtures
│   ├── test_capture.py  # Traffic metrics & capture lifecycle tests
│   ├── test_detector.py # Rule detection, cooldown, state cleanup, and alerts tests
│   ├── test_ml.py       # ML feature extraction, model lifecycle, baseline collection & anomaly detection tests
│   └── test_socket.py   # Test Socket.IO connection and ping
├── requirements.txt     # Python backend dependencies
├── .gitignore           # Git ignore configurations
└── README.md            # Project documentation
```

---

## 4. Detection Architecture: Dual Pipeline (Rules + Machine Learning)

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
          Flask-SocketIO & REST APIs
   (security_event, ml_anomaly, ml_status)
   (/api/alerts, /api/ml/status, /api/ml/metrics)
                      ↓
  React SOC Dashboard (Alerts & ML Anomaly Panel)
```

---

## 5. Machine Learning Anomaly Detection (Isolation Forest)

Phase 4 introduces an unsupervised network traffic anomaly detector powered by Scikit-learn's `IsolationForest`. Unlike signature or rule-based matching, the ML model does not attempt to classify specific attacks. Instead, it evaluates:

> *"Does this aggregated traffic window look significantly different from learned normal traffic?"*

### Numerical Traffic Features (13 Features per Window)
Raw packet bytes are aggregated into fixed-duration time windows (default: 5.0 seconds) and converted into 13 zero-division-safe numerical features:

1. `packets_per_second` (float): Total packets received divided by window duration.
2. `bytes_per_second` (float): Total byte volume divided by window duration.
3. `average_packet_size` (float): Mean packet size in bytes.
4. `tcp_ratio` (float): Fraction of packets using TCP ($0.0$ to $1.0$).
5. `udp_ratio` (float): Fraction of packets using UDP ($0.0$ to $1.0$).
6. `icmp_ratio` (float): Fraction of packets using ICMP ($0.0$ to $1.0$).
7. `syn_ratio` (float): Fraction of TCP packets with SYN flag set.
8. `ack_ratio` (float): Fraction of TCP packets with ACK flag set.
9. `rst_ratio` (float): Fraction of TCP packets with RST flag set.
10. `fin_ratio` (float): Fraction of TCP packets with FIN flag set.
11. `unique_destination_ports` (float): Count of distinct destination ports probed.
12. `unique_source_ips` (float): Count of distinct source IP addresses.
13. `unique_destination_ips` (float): Count of distinct destination IP addresses.

### Model Lifecycle & Baseline Training
The detector operates through distinct lifecycle states (`ModelStatus`):
* `MODEL_NOT_READY`: Model is initialized but not yet trained or loaded.
* `COLLECTING_BASELINE`: Gathers normal traffic windows (default: 10 windows) during benign network conditions. Baseline training is performed **only on normal traffic**, never attack traffic.
* `READY`: Baseline fit completed. Live windows are scored in real time.
* `ERROR`: Model encountered an error or invalid feature matrix.

### Scoring & Anomaly Threshold
* **Scikit-learn Decision Function**: `decision_function(X)` returns negative values for outliers (anomalies) and positive values for normal inliers.
* **Normalized Anomaly Score**: Scaled between $0.0$ (normal) and $1.0$ (anomalous):
  $$\text{Normalized Score} = \text{clip}(0.5 - \text{raw\_score}, 0.0, 1.0)$$
  Windows with normalized score $> 0.5$ indicate an outlier condition.
* **Alert Cooldown**: Anomaly alerts enforce an alert cooldown (`ML_ALERT_COOLDOWN_SEC`, default: 15s) to prevent dashboard alert flooding during sustained anomalies.

### ML REST Endpoints & Socket.IO Events
* `GET /api/ml/status`: Returns model lifecycle status, baseline collection progress, total anomaly count, and latest score.
* `GET /api/ml/metrics`: Returns recent window time series history and the latest 20 anomaly events.
* `ml_anomaly` (Socket.IO event): Emits real-time `MLAnomalyEvent` dictionaries when an anomalous window occurs.
* `ml_status` (Socket.IO event): Emits status updates on connection and lifecycle changes.

---

## 6. Rule-Based Intrusion Detection

The rule-based detector operates independently alongside the ML model:

| Rule Name | Detection Type | Severity | Description & Criteria |
|---|---|---|---|
| **`RULE_PORT_SCAN`** | `PORT_SCAN` | `MEDIUM` | Tracks distinct destination ports probed by a single source IP over a sliding time window. Triggers when unique ports $\ge$ `PORT_SCAN_UNIQUE_PORT_THRESHOLD`. |
| **`RULE_SYN_FLOOD`** | `SYN_FLOOD` | `HIGH` | Tracks unmatched TCP SYN packets ($SYN=1, ACK=0$) per source IP over a sliding window. Triggers when SYN volume $\ge$ `SYN_FLOOD_PACKET_THRESHOLD`. |
| **`RULE_NULL_SCAN`** | `NULL_SCAN` | `HIGH` | Detects stealth probe packets where all 6 TCP control flags ($SYN, ACK, FIN, RST, PSH, URG$) are set to 0. |
| **`RULE_XMAS_SCAN`** | `XMAS_SCAN` | `HIGH` | Detects stealth probe packets where $FIN=1, PSH=1, URG=1$ (and $SYN=0, ACK=0, RST=0$). |

---

## 7. Configuration & Thresholds

Centralized in `backend/config.py` and configurable via environment variables:

| Setting / Environment Variable | Default Value | Purpose |
|---|---|---|
| `PORT_SCAN_WINDOW_SEC` | `10.0` seconds | Sliding time window for tracking unique probed ports |
| `PORT_SCAN_THRESHOLD` | `15` ports | Distinct destination ports required to trigger Port Scan alert |
| `SYN_FLOOD_WINDOW_SEC` | `5.0` seconds | Sliding time window for tracking SYN volume |
| `SYN_FLOOD_THRESHOLD` | `50` packets | Unmatched SYN packets required to trigger SYN Flood alert |
| `ALERT_COOLDOWN_SEC` | `30.0` seconds | Minimum time between duplicate rule alerts for same IP |
| `MAX_TRACKED_IPS` | `1000` | Upper bound on concurrently tracked source IPs |
| `MAX_ALERT_HISTORY` | `100` | Capacity of in-memory security alert store |
| `ML_ENABLED` | `True` | Enable or disable unsupervised Isolation Forest detector |
| `ML_WINDOW_SECONDS` | `5.0` seconds | Aggregation duration for each traffic window |
| `ML_BASELINE_WINDOWS` | `10` | Normal traffic windows required to fit baseline model |
| `ML_N_ESTIMATORS` | `100` | Number of decision trees in Isolation Forest |
| `ML_CONTAMINATION` | `auto` | Expected proportion of outliers in baseline |
| `ML_ALERT_COOLDOWN_SEC`| `15.0` seconds | Cooldown interval between successive ML anomaly alerts |
| `NETSENTINEL_INTERFACE` | `None` (auto) | Network capture interface (`enp0s3`, `lo`, etc.) |

---

## 8. Linux Privileges and Capabilities

Opening Linux raw sockets (`AF_PACKET`) requires the `CAP_NET_RAW` Linux capability:

**Recommended (Grant Linux Capability):**
```bash
sudo setcap cap_net_raw,cap_net_admin+eip .venv/bin/python3
```

**Development / Sudo alternative:**
```bash
sudo .venv/bin/python backend/app.py
```
If started unprivileged, the application remains fully functional, sets `status: "permission_denied"`, and informs the operator without crashing.

---

## 9. Environment Setup & Execution

### Prerequisites
* Linux operating system (kernel supporting `AF_PACKET`)
* Python 3.10+
* Node.js v18+ & npm

### Backend Setup
1. Create and activate a Python virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run automated unit tests:
   ```bash
   pytest tests/
   ```
4. Start backend server:
   ```bash
   python backend/app.py
   ```
   Backend listens on `http://127.0.0.1:5000`.

### Frontend Setup
1. Navigate to the `frontend/` directory:
   ```bash
   cd frontend
   ```
2. Install npm dependencies:
   ```bash
   npm install
   ```
3. Start Vite development server:
   ```bash
   npm run dev
   ```
   Frontend runs on `http://localhost:5173`.
4. Build production frontend assets:
   ```bash
   npm run build
   ```

---

## 10. Automated Testing

All 41 unit tests run deterministically without requiring live network traffic:
```bash
pytest -v tests/
```

Test coverage:
* `tests/test_parser.py`: Binary frame parsing across Ethernet, IPv4, IPv6, TCP, UDP, ICMP, and flag byte handling.
* `tests/test_capture.py`: Raw socket lifecycle, error handling, unprivileged fallbacks, and rolling metrics.
* `tests/test_detector.py`: Port scan, SYN flood, NULL scan, XMAS scan, window expiration, alert cooldowns, and memory bounds.
* `tests/test_ml.py`: 13-feature window extraction, zero-division safety, IsolationForest lifecycle, persistence, corrupted file safety, and anomaly detection.
* `tests/test_health.py`: Health API endpoint.
* `tests/test_socket.py`: Socket.IO handshake and ping/pong.

---

## 11. Current Scope Limitations

* **No Automated IP Blocking**: Firewall mitigation via `iptables` is disabled until Phase 5.
* **No Rule + ML Risk Correlation**: Unsupervised ML and rule detectors currently operate in parallel; composite risk correlation will be implemented in Phase 5.
* **In-Memory Event Store**: SQLite persistent storage of security events will be integrated in Phase 6.

---

## 12. Future Development Roadmap

* **Phase 5 - Risk Engine & Automated IPS**: Correlate rule detections with ML anomaly scores to compute composite threat risk and automate Linux `iptables` blocking and unblocking.
* **Phase 6 - Event Persistence & Telemetry Stream**: Store security events and firewall actions in SQLite, and stream complete telemetry to the React dashboard.
