# NetSentinel — Frontend Visual Review & UI Redesign Inventory

This document catalogs the visual audit screenshots captured from the live, running NetSentinel Security Operations Console frontend following the enterprise UI/UX visual redesign and post-review corrections.

All captures represent genuine application states running against the production Flask backend, React 18 / Vite single-page application, and active SQLite telemetry database.

---

## 1. Environment & Capture Configuration

- **Application URL:** `http://localhost:5173` (Vite dev server proxied to Flask backend on port 5000)
- **Browser Engine:** Mozilla Firefox (Headless Mode via Selenium WebDriver)
- **Zoom Level:** 100%
- **Desktop Viewport:** 1920 × 1080 (Rendered viewport: 1920 × 994)
- **Tablet Viewport:** 768 × 1024 (Rendered viewport: 768 × 938)
- **Responsive Mobile Viewports:**
  - Mobile compact portrait: 390 × 844 (Rendered viewport: 390 × 844)
  - Mobile standard portrait: 500 × 758 (Rendered viewport: 500 × 672)
- **Authentication Session:** Authenticated as primary operator (`admin`, Role: `ADMIN`)
- **Safety Posture:** All authentication inputs masked; no credentials, secrets, session cookies, or private API keys exposed.

---

## 2. Desktop Screenshot Inventory (1920 × 1080)

| Screenshot File | Page Route | Rendered Dimensions | Description |
|---|---|---|---|
| [`01-login.png`](./screenshots/01-login.png) | `/login` | 1920 × 994 | Redesigned enterprise authentication portal featuring obsidian slate card, refined typography, and credential inputs. |
| [`01-login-error.png`](./screenshots/01-login-error.png) | `/login` | 1920 × 994 | Login form with authentication failure alert banner and validation feedback. |
| [`02-dashboard-overview.png`](./screenshots/02-dashboard-overview.png) | `/overview` | 1920 × 994 | Redesigned SOC Overview dashboard displaying KPI metric cards (active incidents, threat score, traffic throughput, engine status). |
| [`02-dashboard-scrolled.png`](./screenshots/02-dashboard-scrolled.png) | `/overview` | 1920 × 994 | SOC Overview scrolled section showing real-time traffic volume area chart with subtle grid lines, incident severity breakdown, and live alert feeds. |
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

## 3. Tablet Screenshot Inventory (768 × 1024)

| Screenshot File | Page Route | Rendered Dimensions | Description |
|---|---|---|---|
| [`tablet-01-dashboard.png`](./screenshots/tablet-01-dashboard.png) | `/overview` | 768 × 938 | Tablet portrait view of the SOC Overview dashboard with responsive 2-column metric cards and adapted chart sizing. |

---

## 4. Responsive Mobile Screenshot Inventory

| Screenshot File | Page Route | Rendered Dimensions | Target Viewport | Description |
|---|---|---|---|---|
| [`responsive-01-login.png`](./screenshots/responsive-01-login.png) | `/login` | 500 × 672 | 500 × 758 | Responsive mobile view of the authentication portal. |
| [`responsive-02-dashboard.png`](./screenshots/responsive-02-dashboard.png) | `/overview` | 390 × 844 | 390 × 844 | Exact compact mobile view (390 × 844) with non-overlapping header (brand title, compact health badge, operator profile button). |
| [`responsive-03-mobile-drawer.png`](./screenshots/responsive-03-mobile-drawer.png) | `/overview` | 500 × 672 | 500 × 758 | Mobile navigation slide-out drawer active via hamburger menu button. |
| [`responsive-04-network.png`](./screenshots/responsive-04-network.png) | `/network` | 500 × 672 | 500 × 758 | Responsive network monitoring view adapted for compact mobile displays. |
| [`responsive-05-incidents.png`](./screenshots/responsive-05-incidents.png) | `/incidents` | 500 × 672 | 500 × 758 | Responsive incidents queue showing mobile-friendly incident cards and status indicators. |
| [`responsive-06-host.png`](./screenshots/responsive-06-host.png) | `/host` | 500 × 672 | 500 × 758 | Responsive host security monitor displaying host resource cards and FIM status. |
| [`responsive-07-firewall.png`](./screenshots/responsive-07-firewall.png) | `/firewall` | 500 × 672 | 500 × 758 | Responsive firewall controls and safe-mode evaluation banner on mobile. |

---

## 5. UI Review Corrections & Verification Log

1. **Mobile Topbar Overhaul:**
   - Redesigned topbar navigation for mobile screens (`<= 768px`). Replaced bulky multi-pill layout with a compact system health badge and an accessible operator profile popover menu.
   - All branding, hamburger drawer trigger, operator username, role badge, telemetry status indicators, and sign-out actions remain accessible without visual overlap or text collisions.
2. **Dashboard Chart Header Alignment:**
   - Resolved heading and action link collision on the Network Traffic Rate card by introducing a flex-wrapping card header with distinct title and subtitle hierarchy.
   - Verified across desktop (1920×1080), laptop (1366×768), and tablet (768×1024) viewports.
3. **Detection & Risk Chart Dark Mode Polish:**
   - Removed jarring white background cursor from the Detection Vector Distribution bar chart by configuring dark slate highlight styling (`rgba(56, 189, 248, 0.08)`).
   - Expanded vertical bar chart Y-axis width to 130px with truncation formatter to eliminate label clipping.
   - Zero-offset margins applied across all time-series and distribution charts to prevent Y-axis tick label clipping.
4. **Network Monitoring Empty States:**
   - Preserved actual kernel packet capture permission-denied warnings.
   - Maintained active AreaChart and BarChart visualization surfaces during 0-packet idle states using genuine zero-count data, eliminating blank loading states and awkward whitespace without fabricating fake data.
5. **Mobile Viewport Overflow Audit:**
   - Evaluated `document.documentElement.scrollWidth` directly against `window.innerWidth` for both target mobile viewports:
     - **390 × 844:** `innerWidth = 390px`, `scrollWidth = 378px` (`≤ 390px`) → **Horizontal Overflow: False**
     - **500 × 758:** `innerWidth = 500px`, `scrollWidth = 488px` (`≤ 500px`) → **Horizontal Overflow: False**
