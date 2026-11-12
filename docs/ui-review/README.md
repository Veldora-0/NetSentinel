# NetSentinel — Frontend Visual Review & UI Screenshot Inventory

This document catalogs the visual audit screenshots captured from the live, running NetSentinel Security Operations Console frontend prior to any UI/UX or styling modifications.

All captures represent genuine application states running against the production Flask backend, React 18 / Vite single-page application, and active SQLite telemetry database.

---

## 1. Environment & Capture Configuration

- **Application URL:** `http://localhost:5173` (Vite dev server proxied to Flask backend on port 5000)
- **Browser Engine:** Mozilla Firefox (Headless Mode via Selenium WebDriver)
- **Zoom Level:** 100%
- **Desktop Viewport:** 1920 × 1080 (Inner rendering: 1920 × 994)
- **Responsive Viewport:** Mobile portrait viewport (~500 × 758, mobile breakpoint `< 768px`)
- **Authentication Session:** Authenticated as primary operator (`admin`, Role: `ADMIN`)
- **Safety Posture:** All authentication inputs masked; no credentials, secrets, session cookies, or private API keys exposed.

---

## 2. Desktop Screenshot Inventory (1920 × 1080)

| Screenshot File | Page Route | Viewport | Description |
|---|---|---|---|
| [`01-login.png`](./screenshots/01-login.png) | `/login` | 1920 × 994 | Unauthenticated login portal showing NetSentinel brand identity, operator access form, and credential inputs. |
| [`01-login-error.png`](./screenshots/01-login-error.png) | `/login` | 1920 × 994 | Login form with authentication failure alert banner and validation feedback. |
| [`02-dashboard-overview.png`](./screenshots/02-dashboard-overview.png) | `/overview` | 1920 × 994 | Main SOC Overview dashboard top section displaying KPI metric cards (active incidents, threat score, traffic throughput, engine status). |
| [`02-dashboard-scrolled.png`](./screenshots/02-dashboard-scrolled.png) | `/overview` | 1920 × 994 | Main SOC Overview scrolled section showing real-time traffic volume area chart, incident severity breakdown, and live alert feeds. |
| [`03-network-monitoring.png`](./screenshots/03-network-monitoring.png) | `/network` | 1920 × 994 | Real-time network telemetry view with bandwidth throughput area chart, packet counters, protocol distribution (TCP/UDP/ICMP), and active sessions. |
| [`04-detection-and-risk.png`](./screenshots/04-detection-and-risk.png) | `/detection` | 1920 × 994 | Hybrid detection console showing unsupervised ML Isolation Forest model status (13 canonical features, baseline progress) and rule-based detector thresholds. |
| [`05-host-security.png`](./screenshots/05-host-security.png) | `/host` | 1920 × 994 | Host security telemetry showing CPU/Memory/Disk utilization, File Integrity Monitoring (FIM) baseline hashes, and SSH brute force protection status. |
| [`06-incidents-list.png`](./screenshots/06-incidents-list.png) | `/incidents` | 1920 × 994 | Incidents queue table showing correlated security incidents with risk scores, severity badges, attack domains, status filters, and time bounds. |
| [`07-incident-detail.png`](./screenshots/07-incident-detail.png) | `/incidents/:incidentId` | 1920 × 994 | Deep-dive incident inspection view showing risk score progression, multi-domain evidence timeline, source attribution, and mitigation actions. |
| [`08-threat-intelligence.png`](./screenshots/08-threat-intelligence.png) | `/threat-intelligence` | 1920 × 994 | Threat Intelligence subsystem status, external provider configuration, reputation cache summary, and queued lookup stats. |
| [`08-threat-intelligence-lookup.png`](./screenshots/08-threat-intelligence-lookup.png) | `/threat-intelligence` | 1920 × 994 | Threat Intelligence interactive IP lookup tool with target search input populated. |
| [`09-firewall.png`](./screenshots/09-firewall.png) | `/firewall` | 1920 × 994 | Firewall management page showing active safe evaluation mode banner (`dry_run=True`, `auto_block=False`), engine status cards, and quarantine records. |
| [`09-firewall-manual-control.png`](./screenshots/09-firewall-manual-control.png) | `/firewall` | 1920 × 994 | Manual IP quarantine control form with target IP input and policy duration selector. |
| [`10-security-history.png`](./screenshots/10-security-history.png) | `/history` | 1920 × 994 | Complete audit log and event history table showing chronological security detections with type filters and pagination. |
| [`11-system-status.png`](./screenshots/11-system-status.png) | `/system` | 1920 × 994 | Backend system telemetry, subsystem readiness health indicators, database stats, and ML configuration parameters. |
| [`12-user-management.png`](./screenshots/12-user-management.png) | `/users` | 1920 × 994 | Role-Based Access Control (RBAC) management page displaying active operator accounts directory and provision operator form. |
| [`12-user-management-reset-action.png`](./screenshots/12-user-management-reset-action.png) | `/users` | 1920 × 994 | User management page with inline credential reset form revealed for selected operator. |
| [`13-sidebar-collapsed.png`](./screenshots/13-sidebar-collapsed.png) | `/overview` | 1920 × 994 | Dashboard overview with primary sidebar collapsed to icon-only compact navigation mode. |
| [`14-not-found-404.png`](./screenshots/14-not-found-404.png) | `/non-existent-page` | 1920 × 994 | Dedicated 404 error page displayed when attempting to access an invalid or unmapped route. |

---

## 3. Responsive Mobile Screenshot Inventory (390 × 844)

| Screenshot File | Page Route | Viewport | Description |
|---|---|---|---|
| [`responsive-01-login.png`](./screenshots/responsive-01-login.png) | `/login` | 500 × 758 | Responsive mobile view of the authentication portal. |
| [`responsive-02-dashboard.png`](./screenshots/responsive-02-dashboard.png) | `/overview` | 500 × 758 | Responsive single-column dashboard layout with vertically stacked metric cards. |
| [`responsive-03-mobile-drawer.png`](./screenshots/responsive-03-mobile-drawer.png) | `/overview` | 500 × 758 | Mobile navigation slide-out drawer active via hamburger menu button. |
| [`responsive-04-network.png`](./screenshots/responsive-04-network.png) | `/network` | 500 × 758 | Responsive network monitoring view adapted for compact mobile displays. |
| [`responsive-05-incidents.png`](./screenshots/responsive-05-incidents.png) | `/incidents` | 500 × 758 | Responsive incidents queue showing mobile-friendly incident cards and status indicators. |
| [`responsive-06-host.png`](./screenshots/responsive-06-host.png) | `/host` | 500 × 758 | Responsive host security monitor displaying host resource cards and FIM status. |
| [`responsive-07-firewall.png`](./screenshots/responsive-07-firewall.png) | `/firewall` | 500 × 758 | Responsive firewall controls and safe-mode evaluation banner on mobile. |

---

## 4. Coverage Summary

- **Total Screenshots Captured:** 26 (19 desktop + 7 responsive mobile).
- **Pages Successfully Accessed (100%):**
  - `/login` (Authentication portal)
  - `/overview` (Main SOC dashboard)
  - `/network` (Network traffic monitoring)
  - `/detection` (ML & rule-based intrusion detection)
  - `/host` (Host security & FIM)
  - `/incidents` (Incident response queue)
  - `/incidents/:incidentId` (Incident detail & evidence timeline)
  - `/threat-intelligence` (Threat intelligence & IP lookup)
  - `/firewall` (Firewall policy & manual quarantine)
  - `/history` (Security event audit history)
  - `/system` (System status & telemetry)
  - `/users` (RBAC user & operator management)
  - `/not-found` (404 error state)
- **Pages That Could Not Be Accessed:** None. All application routes were accessible with operator privileges.
- **UI Components Captured:**
  - Metric KPI cards & status badges
  - Real-time Recharts visualizations (Area charts, Bar charts, Protocol distribution)
  - Tabular data grids (Incidents, Security Events, Monitored Files, Active Operators)
  - Interactive forms (Login, IP lookup, Manual quarantine, User provisioning)
  - Inline modal actions (Password reset, Sidebar toggle, Mobile drawer menu)
  - Error and alert banners (Authentication failure alert, Safe mode evaluation banner)
