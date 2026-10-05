# NetSentinel – Hybrid Network and Host Intrusion Detection and Prevention System

## 1. Project Description
**NetSentinel** is a modern Linux-based hybrid Network Intrusion Detection System (NIDS), Host Intrusion Detection System (HIDS), and Intrusion Prevention System (IPS). It captures and analyzes raw network traffic, applies signature and rule-based detection alongside machine learning anomaly detection (Isolation Forest), evaluates security risk levels, and automatically mitigates threats using Linux `iptables` firewall rules.

> **Implementation Status (Phase 3 Completed):** NetSentinel includes live network packet capture using Linux `AF_PACKET` raw sockets, a complete packet parser, real-time traffic rate metrics, and a stateful **Rule-Based Intrusion Detection Engine** (`detector.py`). The engine identifies **Port Scans**, **SYN Floods**, **NULL Scans**, and **XMAS Scans**, emitting structured `SecurityEvent` alerts in real-time over Flask-SocketIO and via the `/api/alerts` REST endpoint. Automated firewall blocking and machine learning models are reserved for subsequent phases.

---

## 2. Technology Stack

### Backend
* **Python 3**
* **Linux `AF_PACKET` Raw Sockets** - Kernel-level raw Ethernet frame capture
* **Flask** - REST API framework (`/api/health`, `/api/metrics`, `/api/alerts`)
* **Flask-SocketIO** - Real-time WebSocket event communication (`traffic_metrics` and `security_event` streams)
* **Flask-SQLAlchemy / SQLAlchemy** - Database ORM
* **SQLite** - Embedded event & telemetry persistence foundation
* **psutil** - System telemetry monitoring
* **pytest** - Automated test suite (29 tests)

### Frontend
* **React 18** - UI framework
* **Vite** - High-performance frontend build tool & proxy server
* **JavaScript (ES6+ / JSX)** - Core frontend scripting
* **Recharts** - Real-time traffic rate visualization charts
* **Lucide React** - Modern SOC-style UI iconography

---

## 3. Directory Structure

```
NetSentinel/
│
├── backend/
│   ├── app.py           # Flask app factory, API routes, Socket.IO & capture lifecycle
│   ├── config.py        # Centralized settings, network interface selection, detection thresholds
│   ├── capture.py       # AF_PACKET raw socket capture engine & rolling metrics aggregator
│   ├── parser.py        # Complete Ethernet, IPv4, IPv6, TCP, UDP, ICMP packet parser
│   ├── detector.py      # Rule-based intrusion detection engine & state manager
│   ├── risk_engine.py   # Composite threat risk evaluation skeleton (Phase 5)
│   ├── firewall.py      # Linux iptables firewall manager skeleton (Phase 5)
│   ├── database.py      # SQLAlchemy database configuration and model base
│   └── telemetry.py     # System telemetry & resource monitor module
│
├── frontend/
│   ├── src/
│   │   ├── components/  # Modular UI components (Header, DashboardCard, etc.)
│   │   ├── pages/       # Page views (Dashboard with live alerts & traffic telemetry)
│   │   ├── services/    # REST API & Socket.IO client connections
│   │   ├── App.jsx      # Root application component
│   │   ├── App.css      # SOC dark theme styling
│   │   └── main.jsx     # React entry point
│   ├── index.html       # HTML entry point
│   ├── package.json     # Node dependencies and scripts
│   └── vite.config.js   # Vite server setup & backend API proxy configuration
│
├── data/                # Directory for SQLite database storage
├── tests/               # Automated unit tests for parser, capture, detector, API, and Socket.IO
│   ├── test_health.py   # Test GET /api/health
│   ├── test_parser.py   # Parser unit tests with binary packet fixtures
│   ├── test_capture.py  # Traffic metrics & capture lifecycle tests
│   ├── test_detector.py # Rule detection, cooldown, state cleanup, and alerts tests
│   └── test_socket.py   # Test Socket.IO connection and ping
├── requirements.txt     # Python backend dependencies
├── .gitignore           # Git ignore configurations
└── README.md            # Project documentation
```

---

## 4. Phase 3 Architecture: Detection Pipeline & Security Events

```text
Linux Network Interface (e.g., enp0s3)
                 ↓
      AF_PACKET Raw Socket
                 ↓
     backend/capture.py (Capture Loop)
                 ↓
     backend/parser.py (Structured ParsedPacket)
                 ↓
     backend/detector.py (TrafficDetector Rule Engine)
        ├── Port Scan Rule (Stateful: unique probed ports in window)
        ├── SYN Flood Rule (Stateful: SYN request volume in window)
        ├── NULL Scan Rule (Stateless: TCP control flags == 0)
        └── XMAS Scan Rule (Stateless: FIN + PSH + URG active)
                 ↓
      Structured SecurityEvent
                 ↓
  ┌──────────────┴──────────────┐
  ↓                             ↓
Flask-SocketIO            In-Memory Event Store (deque)
(Event: "security_event") (Endpoint: GET /api/alerts)
  ↓                             ↓
React Dashboard: Live Security Alerts & Breakdown Stats
```

### Detection Rules & Criteria

| Rule Name | Detection Type | Severity | Description & Criteria |
|---|---|---|---|
| **`RULE_PORT_SCAN`** | `PORT_SCAN` | `MEDIUM` | Tracks distinct destination ports probed by a single source IP over a sliding time window. Triggers when unique ports $\ge$ `PORT_SCAN_UNIQUE_PORT_THRESHOLD`. |
| **`RULE_SYN_FLOOD`** | `SYN_FLOOD` | `HIGH` | Tracks unmatched TCP SYN packets ($SYN=1, ACK=0$) per source IP over a sliding window. Triggers when SYN volume $\ge$ `SYN_FLOOD_PACKET_THRESHOLD`. |
| **`RULE_NULL_SCAN`** | `NULL_SCAN` | `HIGH` | Detects stealth probe packets where all 6 TCP control flags ($SYN, ACK, FIN, RST, PSH, URG$) are set to 0. |
| **`RULE_XMAS_SCAN`** | `XMAS_SCAN` | `HIGH` | Detects stealth probe packets where $FIN=1, PSH=1, URG=1$ (and $SYN=0, ACK=0, RST=0$). |

### Security Event Schema
Each alert is represented as a structured `SecurityEvent` with JSON-serializable fields:
* `event_id`: Unique identifier (hex string).
* `timestamp`: Unix timestamp of detection.
* `detection_type`: `PORT_SCAN`, `SYN_FLOOD`, `NULL_SCAN`, or `XMAS_SCAN`.
* `severity`: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
* `source_ip`: Attacker IP address.
* `destination_ip`: Target IP address.
* `protocol`: Transport protocol (`TCP`, `UDP`).
* `source_port`: Attacker port.
* `destination_port`: Target port.
* `description`: Clear textual description of the detected anomaly.
* `evidence`: Dictionary containing counts, window parameters, and flag values.
* `rule_name`: Internal rule identifier.

### Alert Cooldown & State Management
* **Alert De-duplication**: To prevent alert fatigue from ongoing attacks, the detector enforces an alert cooldown (`ALERT_COOLDOWN_SECONDS`, default: 30s) per `(source_ip, rule_name)` pair.
* **Bounded Memory**: Probing history per IP is kept in sliding `deque` buffers pruned on every packet. State for inactive IPs is pruned automatically every 60 seconds, and the total tracked IP count is capped at `MAX_TRACKED_IPS` (default: 1000).
* **Event Store**: Alerts are stored in a bounded in-memory `deque` (latest 100 events) and served in newest-first order via `/api/alerts`.

---

## 5. Configuration & Thresholds

All thresholds are centralized in `backend/config.py` and can be overridden via environment variables:

| Setting / Environment Variable | Default Value | Purpose |
|---|---|---|
| `PORT_SCAN_WINDOW_SEC` | `10.0` seconds | Sliding time window for tracking unique probed ports |
| `PORT_SCAN_THRESHOLD` | `15` ports | Distinct destination ports required to trigger Port Scan alert |
| `SYN_FLOOD_WINDOW_SEC` | `5.0` seconds | Sliding time window for tracking SYN volume |
| `SYN_FLOOD_THRESHOLD` | `50` packets | Unmatched SYN packets required to trigger SYN Flood alert |
| `ALERT_COOLDOWN_SEC` | `30.0` seconds | Minimum time between duplicate alerts for same IP and rule |
| `MAX_TRACKED_IPS` | `1000` | Upper bound on concurrently tracked source IPs |
| `MAX_ALERT_HISTORY` | `100` | Capacity of in-memory security alert store |
| `NETSENTINEL_INTERFACE` | `None` (auto) | Network capture interface (`enp0s3`, `lo`, etc.) |

---

## 6. Linux Privileges and Capabilities

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

## 7. Environment Setup & Execution

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

## 8. Controlled Verification & Testing

> **Important**: Testing must only be conducted in authorized, controlled lab environments (such as an isolated local virtual machine or test network). Never test against unauthorized networks.

Synthetic tests for all rules run automatically without requiring live attack traffic:
```bash
pytest -v tests/test_detector.py
```

---

## 9. Current Scope Limitations

* **No Automated IP Blocking**: Firewall mitigation via `iptables` is disabled (dry-run skeleton) until Phase 5.
* **No Machine Learning**: Isolation Forest anomaly scoring will be added in Phase 4.
* **In-Memory Alert Store**: SQLite persistent storage of security events will be integrated in Phase 6.

---

## 10. Future Development Roadmap

* **Phase 4 - Machine Learning Anomaly Detection**: Train and integrate Scikit-learn's Isolation Forest model on traffic feature vectors.
* **Phase 5 - Risk Engine & Automated IPS**: Compute risk decisions and automate Linux `iptables` firewall blocking and unblocking.
* **Phase 6 - Event Persistence & Telemetry Stream**: Store security alerts in SQLite and stream complete telemetry to the React dashboard.
