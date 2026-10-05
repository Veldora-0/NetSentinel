# NetSentinel – Hybrid Network and Host Intrusion Detection and Prevention System

## 1. Project Description
**NetSentinel** is a modern Linux-based hybrid Network Intrusion Detection System (NIDS), Host Intrusion Detection System (HIDS), and Intrusion Prevention System (IPS). It captures and analyzes raw network traffic, applies signature and rule-based detection alongside machine learning anomaly detection (Isolation Forest), evaluates security risk levels, and automatically mitigates threats using Linux `iptables` firewall rules.

> **Implementation Status (Phase 2 Completed):** NetSentinel includes live network packet capture using Linux `AF_PACKET` raw sockets, a full packet parser for Ethernet, IPv4, IPv6, TCP, UDP, and ICMP, rolling traffic rate calculation (packets/sec and bytes/sec), and real-time Socket.IO streaming to the React dashboard. Intrusion detection rules, ML models, and automated firewall blocks will be implemented in subsequent phases.

---

## 2. Technology Stack

### Backend
* **Python 3**
* **Linux `AF_PACKET` Raw Sockets** - Kernel-level raw Ethernet frame capture
* **Flask** - REST API framework
* **Flask-SocketIO** - Real-time WebSocket event communication (`traffic_metrics` event)
* **Flask-SQLAlchemy / SQLAlchemy** - Database ORM
* **SQLite** - Embedded event & telemetry persistence
* **psutil** - System telemetry monitoring
* **pytest** - Automated test suite

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
│   ├── config.py        # Centralized settings, network interface selection, thresholds
│   ├── capture.py       # AF_PACKET raw socket capture engine & rolling metrics aggregator
│   ├── parser.py        # Complete Ethernet, IPv4, IPv6, TCP, UDP, ICMP packet parser
│   ├── detector.py      # Rule-based intrusion detector architectural skeleton (Phase 3)
│   ├── risk_engine.py   # Composite threat risk evaluation skeleton (Phase 5)
│   ├── firewall.py      # Linux iptables firewall manager skeleton (Phase 5)
│   ├── database.py      # SQLAlchemy database configuration and model base
│   └── telemetry.py     # System telemetry & resource monitor module
│
├── frontend/
│   ├── src/
│   │   ├── components/  # Modular UI components (Header, DashboardCard, etc.)
│   │   ├── pages/       # Page views (Dashboard with real-time traffic telemetry)
│   │   ├── services/    # REST API & Socket.IO client connections
│   │   ├── App.jsx      # Root application component
│   │   ├── App.css      # SOC dark theme styling
│   │   └── main.jsx     # React entry point
│   ├── index.html       # HTML entry point
│   ├── package.json     # Node dependencies and scripts
│   └── vite.config.js   # Vite server setup & backend API proxy configuration
│
├── data/                # Directory for SQLite database storage
├── tests/               # Automated unit tests for parser, capture, API, and Socket.IO
│   ├── test_health.py   # Test GET /api/health
│   ├── test_parser.py   # Parser unit tests with binary packet fixtures
│   ├── test_capture.py  # Traffic metrics & capture lifecycle tests
│   └── test_socket.py   # Test Socket.IO connection and ping
├── requirements.txt     # Python backend dependencies
├── .gitignore           # Git ignore configurations
└── README.md            # Project documentation
```

---

## 4. Architecture & Implementation (Phase 2)

```text
Linux Network Interface (e.g., enp0s3)
                 ↓
      AF_PACKET Raw Socket
                 ↓
     backend/capture.py (Capture Loop)
                 ↓
     backend/parser.py (Structured ParsedPacket)
                 ↓
     TrafficMetrics (Rolling Rates & Protocol Counters)
                 ↓
    Flask-SocketIO (Event: "traffic_metrics")
                 ↓
     React Dashboard (Live Telemetry & Recharts)
```

### Packet Parser (`backend/parser.py`)
Converts raw bytes into a strongly typed `ParsedPacket` dataclass:
* **Ethernet**: Source MAC, Destination MAC, EtherType (IPv4, IPv6, ARP, 802.1Q).
* **IPv4**: Source IP, Destination IP, Protocol (TCP, UDP, ICMP, IGMP), TTL, Header Length, Total Length.
* **IPv6**: Source IPv6, Destination IPv6, Next Header / Protocol, Hop Limit, Payload Length.
* **TCP**: Source Port, Destination Port, Sequence Number, Acknowledgement Number, Header Length, and individual TCP flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`).
* **UDP**: Source Port, Destination Port, Datagram Length.
* **ICMP / ICMPv6**: Message Type, Code.
* **Robustness**: Truncated frames, malformed headers, or unknown protocols are handled gracefully without crashing the capture thread.

### Packet Capture & Metrics (`backend/capture.py`)
* Manages the lifecycle of a Linux `AF_PACKET` raw socket (`ETH_P_ALL = 0x0003`).
* Binds to the designated interface or auto-detects the active gateway interface.
* Aggregates live traffic metrics: total packets, total bytes, rolling packets/second (pps), rolling bytes/second (bps), and individual protocol counters (TCP, UDP, ICMP, other).
* Safe error handling: If run without required raw socket privileges, the module gracefully flags `status: "permission_denied"` and avoids crashing the Flask application.

### Real-Time Dashboard Integration
* Flask-SocketIO emits periodic `traffic_metrics` events (default: 1.0s interval) to connected dashboard clients.
* React displays live throughput, packets/sec, total volume, protocol breakdown pills, and a real-time Recharts area trend graph.

---

## 5. Linux Privileges and Network Interface Configuration

### Network Interface Selection
By default, NetSentinel automatically discovers the active Linux network interface by inspecting `/proc/net/route` and `psutil`. You can explicitly specify an interface via environment variable:
```bash
export NETSENTINEL_INTERFACE=enp0s3
```
Or configure `NETWORK_INTERFACE` in `backend/config.py`.

### Linux Privileges for `AF_PACKET`
Opening Linux raw sockets (`AF_PACKET`) requires the `CAP_NET_RAW` Linux capability. To run NetSentinel securely without running the entire application as `root`:

**Recommended (Grant Linux Capability):**
```bash
sudo setcap cap_net_raw,cap_net_admin+eip .venv/bin/python3
```
*(Replace `.venv/bin/python3` with your active python binary path)*

**Development / Sudo alternative:**
```bash
sudo .venv/bin/python backend/app.py
```
If started without privileges, the backend continues running normally and indicates `Capture Status: PERMISSION_DENIED` on the dashboard.

---

## 6. Environment Setup & Execution

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
3. Run the automated test suite:
   ```bash
   pytest tests/
   ```
4. Start the backend server:
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
   Frontend will run on `http://localhost:5173`.

4. Build production frontend assets:
   ```bash
   npm run build
   ```

---

## 7. Current Limitations

* **No Attack Rules Yet**: Signature detection (Port scan, SYN flood, NULL scan, XMAS scan) is reserved for Phase 3.
* **No Automated Blocking**: Firewall mitigation via `iptables` is disabled (dry-run skeleton) until Phase 5.
* **No Machine Learning**: Isolation Forest anomaly scoring will be added in Phase 4.

---

## 8. Future Development Roadmap

* **Phase 3 - Rule-Based Detection Engine**: Implement detection algorithms for Port Scans, SYN Floods, NULL Scans, and XMAS Scans.
* **Phase 4 - Machine Learning Anomaly Detection**: Train and integrate Scikit-learn's Isolation Forest model on traffic feature vectors.
* **Phase 5 - Risk Engine & Automated IPS**: Compute risk decisions and automate Linux `iptables` firewall blocking and unblocking.
* **Phase 6 - Event Persistence & Telemetry Stream**: Store security alerts in SQLite and stream complete telemetry to the React dashboard.
