# NetSentinel – Hybrid Network and Host Intrusion Detection and Prevention System

## 1. Project Description
**NetSentinel** is a modern Linux-based hybrid Network Intrusion Detection System (NIDS), Host Intrusion Detection System (HIDS), and Intrusion Prevention System (IPS). It captures and analyzes raw network traffic, applies signature and rule-based detection alongside machine learning anomaly detection (Isolation Forest), evaluates security risk levels, and automatically mitigates threats using Linux `iptables` firewall rules.

> **Phase 1 Implementation Notice:** This repository contains the **initial project foundation and architecture only**. Intrusion detection algorithms, raw packet sniffing, iptables firewall execution, and machine learning models are reserved for future phases.

---

## 2. Technology Stack

### Backend
* **Python 3**
* **Flask** - REST API framework
* **Flask-SocketIO** - Real-time WebSocket event communication
* **Flask-SQLAlchemy / SQLAlchemy** - Database ORM
* **SQLite** - Embedded event & telemetry persistence
* **psutil** - System telemetry monitoring
* **pytest** - Automated test suite

### Frontend
* **React 18** - UI framework
* **Vite** - High-performance frontend build tool & proxy server
* **JavaScript (ES6+ / JSX)** - Core frontend scripting
* **Recharts** - Data visualization and charts (reserved for telemetry & alert trends)
* **Lucide React** - Modern SOC-style UI iconography

---

## 3. Directory Structure

```
NetSentinel/
│
├── backend/
│   ├── app.py           # Flask app factory, API routes, Socket.IO entry point
│   ├── config.py        # Centralized settings and future detection thresholds
│   ├── parser.py        # Raw packet parsing architectural skeleton
│   ├── detector.py      # Rule-based intrusion detector architectural skeleton
│   ├── risk_engine.py   # Composite threat risk evaluation architectural skeleton
│   ├── firewall.py      # Linux iptables firewall manager architectural skeleton
│   ├── database.py      # SQLAlchemy database configuration and model base
│   └── telemetry.py     # System telemetry & resource monitor module
│
├── frontend/
│   ├── src/
│   │   ├── components/  # Modular UI components (Header, DashboardCard, etc.)
│   │   ├── pages/       # Page views (Dashboard)
│   │   ├── services/    # REST API & Socket.IO client connections
│   │   ├── App.jsx      # Root application component
│   │   ├── App.css      # SOC dark theme styling
│   │   └── main.jsx     # React entry point
│   ├── index.html       # HTML entry point
│   ├── package.json     # Node dependencies and scripts
│   └── vite.config.js   # Vite server setup & backend API proxy configuration
│
├── data/                # Directory for SQLite database storage
├── tests/               # Automated unit tests for backend API & Socket.IO
├── requirements.txt     # Python backend dependencies
├── .gitignore           # Git ignore configurations
└── README.md            # Project documentation
```

---

## 4. Current Architecture & Implementation Status

### Backend Architecture
* **`app.py`**: Configured with Flask CORS and Flask-SocketIO. Exposes `/api/health` endpoint and handles WebSocket connection lifecycle (`connect`, `disconnect`, `ping_server`).
* **`config.py`**: Centralizes application configurations, database pathing, and placeholder threshold definitions for rule detection, risk scoring, and firewall rules.
* **`database.py`**: SQLAlchemy instance setup pointing to `data/netsentinel.db`.
* **`parser.py`**: Module interface for raw packet parsing (Ethernet, IP, TCP headers).
* **`detector.py`**: Module interface for rule detection (Port Scan, SYN Flood, NULL Scan, XMAS Scan).
* **`risk_engine.py`**: Module interface for risk calculation and decision logic.
* **`firewall.py`**: Interface for iptables rule creation (dry-run simulation mode).
* **`telemetry.py`**: System resource stats collector utilizing `psutil`.

### Frontend Architecture
* **React + Vite Dashboard**: Clean cybersecurity monitoring interface with real-time API and Socket.IO connection status indicators.
* **Vite Proxy**: Configured in `vite.config.js` to proxy `/api` and `/socket.io` requests to Flask at `http://127.0.0.1:5000`.
* **Real-time States**: Displays dynamic `Connected`/`Disconnected` status for backend services along with structured placeholder panels for live alerts, traffic, blocked IPs, system resources, and detection statistics without generating fake attack numbers.

---

## 5. Environment Setup & Execution

### Prerequisites
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
3. Run backend tests:
   ```bash
   pytest tests/
   ```
4. Start Flask backend server:
   ```bash
   python backend/app.py
   ```
   Backend will listen on `http://127.0.0.1:5000`.

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

## 6. Future Development Roadmap

* **Phase 2 - Network Packet Capture & Parsing**: Implement raw packet capture via Linux `AF_PACKET` raw sockets and parse Ethernet/IP/TCP/UDP packet headers.
* **Phase 3 - Rule-Based Detection Engine**: Build algorithms for Port Scan, SYN Flood, NULL Scan, and XMAS Scan detection.
* **Phase 4 - Anomaly Detection**: Integrate Scikit-learn's Isolation Forest model for baseline network behavior profiling and anomaly detection.
* **Phase 5 - Risk Engine & Automated Prevention**: Implement risk scoring and automate Linux `iptables` rules for dynamic IP blocking/unblocking.
* **Phase 6 - Event Persistence & Telemetry Stream**: Store security alerts in SQLite and stream live telemetry & traffic charts via Socket.IO to the React dashboard.
