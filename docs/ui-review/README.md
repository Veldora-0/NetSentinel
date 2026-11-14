# NetSentinel — Frontend Visual Review & UI Inventory

This document catalogs the visual audit screenshots captured from the live, running NetSentinel network intrusion detection and security monitoring application.

All captures represent genuine application states running against the production Flask backend, React 18 / Vite single-page application, and active SQLite telemetry database.

### Current appearance

The screenshots below document the earlier dark-only palette. The current dashboard defaults to a neutral light palette and includes a top-bar theme control for switching to dark mode. The selected theme is stored in browser local storage under `netsentinel_theme`; changing it does not alter application behavior. Existing route and interaction inventory remains useful, but the screenshots should be refreshed before using this document as a current visual reference.

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
| [`01-login.png`](./screenshots/01-login.png) | `/login` | 1920 × 994 | Authentication portal featuring NetSentinel branding, subtitle, and credential inputs. |
| [`01-login-error.png`](./screenshots/01-login-error.png) | `/login` | 1920 × 994 | Login form with authentication failure alert banner and validation feedback. |
| [`02-dashboard-overview.png`](./screenshots/02-dashboard-overview.png) | `/overview` | 1920 × 994 | Overview dashboard displaying KPI metric cards and 3 evenly distributed charts (Traffic Rate, Security Event Severity, Host Resources) spanning the full width. |
| [`02-dashboard-scrolled.png`](./screenshots/02-dashboard-scrolled.png) | `/overview` | 1920 × 994 | Overview scrolled section showing active correlated incidents table, recent risk assessments feed, and firewall defense posture. |
| [`03-network-monitoring.png`](./screenshots/03-network-monitoring.png) | `/network` | 1920 × 994 | Network monitoring view with bandwidth throughput area chart, packet counters, protocol distribution, and active capture status. |
| [`04-detection-and-risk.png`](./screenshots/04-detection-and-risk.png) | `/detection` | 1920 × 994 | Detection & Risk console showing unsupervised ML Isolation Forest model lifecycle status and rule-based detector thresholds. |
| [`05-host-security.png`](./screenshots/05-host-security.png) | `/host` | 1920 × 994 | Host security telemetry showing CPU/Memory utilization history, SSH brute-force monitor, and File Integrity Monitoring (FIM) baselines. |
| [`06-incidents-list.png`](./screenshots/06-incidents-list.png) | `/incidents` | 1920 × 994 | Incidents queue table showing correlated security incidents with risk scores, severity badges, and dark-themed investigate buttons. |
| [`07-incident-detail.png`](./screenshots/07-incident-detail.png) | `/incidents/:incidentId` | 1920 × 994 | Deep-dive incident inspection view showing chronological attack timeline with distinct severity border mapping and evidence attributes. |
| [`08-threat-intelligence.png`](./screenshots/08-threat-intelligence.png) | `/threat-intelligence` | 1920 × 994 | Threat Intelligence view showing reputation provider status, cache entries, and lookup metrics. |
| [`08-threat-intelligence-lookup.png`](./screenshots/08-threat-intelligence-lookup.png) | `/threat-intelligence` | 1920 × 994 | Threat Intelligence interactive IP lookup form with target search input populated. |
| [`09-firewall.png`](./screenshots/09-firewall.png) | `/firewall` | 1920 × 994 | Firewall management page showing active safe evaluation mode banner (`dry_run=True`, `auto_block=False`), engine status cards, and quarantine records. |
| [`09-firewall-manual-control.png`](./screenshots/09-firewall-manual-control.png) | `/firewall` | 1920 × 994 | Manual IP quarantine control form example with target IP input and policy duration selector. |
| [`10-security-history.png`](./screenshots/10-security-history.png) | `/history` | 1920 × 994 | Complete audit log and event history table showing chronological security detections with type filters and pagination. |
| [`11-system-status.png`](./screenshots/11-system-status.png) | `/system` | 1920 × 994 | System Status view presenting consolidated runtime service metric cards (Detection Engine, REST API, WebSocket Stream, Database, Firewall Netfilter), background workers table, and host parameters without duplicated pills. |
| [`12-user-management.png`](./screenshots/12-user-management.png) | `/users` | 1920 × 994 | User Management page displaying active user accounts directory and create user form. |
| [`12-user-management-reset-action.png`](./screenshots/12-user-management-reset-action.png) | `/users` | 1920 × 994 | User management page with inline credential reset form revealed for selected operator. |
| [`13-sidebar-collapsed.png`](./screenshots/13-sidebar-collapsed.png) | `/overview` | 1920 × 994 | Dashboard overview with primary sidebar collapsed to icon-only compact navigation mode. |
| [`14-not-found-404.png`](./screenshots/14-not-found-404.png) | `/non-existent-page` | 1920 × 994 | Dedicated 404 error page displayed when attempting to access an invalid or unmapped route. |

---

## 3. Tablet Screenshot Inventory (768 × 1024)

| Screenshot File | Page Route | Rendered Dimensions | Description |
|---|---|---|---|
| [`tablet-01-dashboard.png`](./screenshots/tablet-01-dashboard.png) | `/overview` | 768 × 938 | Tablet portrait view of the Overview dashboard with responsive 2-column metric cards and adapted chart sizing. |

---

## 4. Responsive Mobile Screenshot Inventory

| Screenshot File | Page Route | Rendered Dimensions | Target Viewport | Description |
|---|---|---|---|---|
| [`responsive-01-login.png`](./screenshots/responsive-01-login.png) | `/login` | 500 × 672 | 500 × 758 | Responsive mobile view of the authentication portal. |
| [`responsive-02-dashboard.png`](./screenshots/responsive-02-dashboard.png) | `/overview` | 390 × 844 | 390 × 844 | Exact compact mobile view (390 × 844) with non-overlapping header. |
| [`responsive-03-mobile-drawer.png`](./screenshots/responsive-03-mobile-drawer.png) | `/overview` | 500 × 672 | 500 × 758 | Mobile navigation slide-out drawer active via hamburger menu button. |
| [`responsive-04-network.png`](./screenshots/responsive-04-network.png) | `/network` | 500 × 672 | 500 × 758 | Responsive network monitoring view adapted for compact mobile displays. |
| [`responsive-05-incidents.png`](./screenshots/responsive-05-incidents.png) | `/incidents` | 500 × 672 | 500 × 758 | Responsive incidents queue showing mobile-friendly incident cards and status indicators. |
| [`responsive-06-host.png`](./screenshots/responsive-06-host.png) | `/host` | 500 × 672 | 500 × 758 | Responsive host security monitor displaying host resource cards and FIM status. |
| [`responsive-07-firewall.png`](./screenshots/responsive-07-firewall.png) | `/firewall` | 500 × 672 | 500 × 758 | Responsive firewall controls and safe-mode evaluation banner on mobile. |

---

## 5. UI Review Corrections & Verification Log

1. **Topbar Navigation Streamlining & Status Relocation:**
   - Streamlined topbar navigation across desktop, tablet, and mobile viewports. Removed secondary telemetry indicators (`Engine`, `API`, `Stream`) from the global topbar and consolidated runtime health reporting onto the System Status page (`/system`).
   - Removed redundant NetSentinel logo and tagline branding from the desktop topbar (already anchored in the persistent sidebar), dedicating the topbar cleanly to operator identity, role badge, and sign-out actions.
   - For mobile screens (`<= 768px`), replaced multi-pill layouts with an accessible operator profile menu. All navigation controls, hamburger menu triggers, and user controls remain collision-free.
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
6. **Desktop & Laptop Experience Polish:**
   - **Incident Detail Workspace (`/incidents/:id`):** Styled investigation tabs with dark obsidian pills and sky-blue active indicator; restructured chronological attack timeline into distinct cards with colored severity borders, clear timestamp hierarchy, and bounded, wrapped evidence code panels; styled operator action inputs and state transition controls.
   - **Host Security (`/host`):** Styled telemetry resource gauges (CPU, RAM, Disk, Load) with dedicated labels and percentage bars; separated SSH authentication tracker and Process integrity observer into structured metric rows; formatted FIM monitored paths as individual monospace pills (`/etc/passwd`, `/etc/group`, `/etc/ssh/sshd_config`).
   - **Uniform Dark Form Controls:** Styled all native `<select>`, `<input>`, and `<textarea>` elements across Incidents, History, Firewall, and Threat Intelligence using consistent dark slate backgrounds (`#0b1120`), subtle borders (`#1e293b`), and sky-blue focus rings.
   - **Global Custom Dark Scrollbars:** Styled `::-webkit-scrollbar` application-wide with obsidian tracks (`#090d16`) and slate thumbs (`#1e293b`), eliminating native bright white browser scrollbars on tables and panels.
   - **Detection & Risk (`/detection`):** Formatted model lifecycle metrics list with clear row borders and label/value separation; neutralized chart hover tooltips during screenshot capture for clean graph presentation.
   - **System Status (`/system`):** Formatted Runtime Environment & Parameters section with clean cards, distinct label/value rows, and readable path strings.
   - **Network Monitoring (`/network`):** Clarified zero-frame idle states (`"0 frames captured — awaiting traffic"`) while keeping both live throughput and protocol distribution charts active with genuine zero-count telemetry.
7. **UI Review Precision Polish:**
   - **Incidents List (`/incidents`):** Styled `.btn-investigate` controls with dark obsidian backgrounds, subtle sky-blue borders, and compact proportions to match adjacent `.btn-action-ack` controls.
   - **Incident Detail Timeline Colors (`/incidents/:id`):** Aligned MEDIUM event timeline card left-border color to `#fbbf24` (exact amber-gold of `.badge-medium`), eliminating visual confusion with HIGH events (`#f97316`).
   - **Evidence Text Readability:** Boosted contrast and sizing for evidence metadata (`0.78rem`, `#cbd5e1`, `line-height: 1.5`) while maintaining compact panel bounding and native scrollability.
   - **Network Privilege Messaging (`/network`):** When packet capture status is `PERMISSION_DENIED` (running unprivileged without `CAP_NET_RAW`), explicitly notifies the operator (`"Packet capture unavailable until required privileges are granted"`) rather than displaying a generic idle state.
8. **Final Design Refinement & Layout Balancing:**
   - **Removed Duplicated Status Indicators:** Removed the compact status-pills row on `/system`. Subsystem health is now cleanly represented solely in the 5 comprehensive metric cards (Detection Engine, REST API, WebSocket Stream, Database, and Firewall Netfilter), preserving real backend probe sources without redundancy.
   - **Removed Redundant Topbar Branding:** The desktop topbar no longer duplicates the NetSentinel logo and tagline already present in the primary sidebar navigation. Desktop topbar cleanly hosts user identity, role badge, and sign-out controls.
   - **Balanced Dashboard Chart Distribution:** Eliminated the empty gap on the right side of the dashboard by implementing `.overview-charts-grid` with a dedicated 3-column distribution (`repeat(3, minmax(0, 1fr))`). All three charts (Traffic Rate, Severity Distribution, and Host Resources) now evenly occupy the full available horizontal space.
   - **Consistent, Natural Branding:** Standardized application labels to concise, authentic names across all views (`NetSentinel`, `Overview`, `Sign in to NetSentinel`, `404: The requested page could not be found`, `Network Monitoring`, `Detection & Risk`, `Host Security`, `Incidents`, `Firewall Management`, `Security History`, `System Status`, `Threat Intelligence`, `User Management`).
9. **Live Host & System Status Data:**
   - Corrected the Host Security page to read the SSH and process monitor fields returned by `/api/host/status`, including log path, threshold, baseline, and tracked process/source counts. The page now reports real worker status instead of `UNKNOWN` and zero values.
   - Added runtime environment, process ID, and telemetry worker state to `/api/system/status` so the System Status page no longer shows fallback values for live diagnostics.
   - FIM metadata evidence now shows changed mode, owner UID, and group GID values, avoiding identical mode values when an ownership change triggered the event.
   - Detection and incident pages now surface API failures instead of presenting failed requests as empty risk or incident results; System Status reports the API as offline when it cannot be reached.
10. **Firewall Status Accuracy:**
   - The Overview firewall posture now reads the live firewall configuration instead of displaying a hardcoded evaluation-mode message.
   - System diagnostics now include the firewall enabled flag and chain, distinguish disabled, dry-run, live, and unavailable states, and display the capability-check reason when live enforcement is configured but unavailable.
