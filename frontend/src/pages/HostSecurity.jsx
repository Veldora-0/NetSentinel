import React, { useState, useEffect, useCallback } from 'react';
import {
  Terminal,
  FileText,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Cpu,
  ShieldAlert,
  Activity,
  Layers,
  Clock,
  HardDrive,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';
import { PageHeader } from '../components/layout/PageHeader';
import { MetricCard } from '../components/common/MetricCard';
import { StatusBadge } from '../components/common/StatusBadge';
import { DashboardCard } from '../components/DashboardCard';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { useSocketEvent } from '../hooks/useSocketEvent';
import {
  fetchHostStatus,
  fetchTelemetryCurrent,
  fetchTelemetryHistory,
  fetchFimStatus,
  fetchFimEvents,
  triggerFimRebaseline,
} from '../services/api';
import {
  formatBytes,
  formatNumber,
  formatPercent,
  safeNumber,
  formatAlertTime,
  formatFullTime,
  getRiskBadgeClass,
} from '../utils/formatters';

export default function HostSecurity() {
  const [hostStatus, setHostStatus] = useState(null);
  const [hostTelemetry, setHostTelemetry] = useState(null);
  const [telemetryHistory, setTelemetryHistory] = useState([]);
  const [fimStatus, setFimStatus] = useState(null);
  const [fimEvents, setFimEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showRebaselineConfirm, setShowRebaselineConfirm] = useState(false);
  const [rebaselining, setRebaselining] = useState(false);
  const [rebaselineMsg, setRebaselineMsg] = useState(null);

  const loadData = useCallback(async () => {
    try {
      setError(null);
      const [hStatus, telem, telemHist, fStatus, fEventsRes] = await Promise.all([
        fetchHostStatus(),
        fetchTelemetryCurrent(),
        fetchTelemetryHistory(30),
        fetchFimStatus(),
        fetchFimEvents({ limit: 50 }),
      ]);
      setHostStatus(hStatus);
      setHostTelemetry(telem?.telemetry || telem);
      if (telemHist?.history) {
        const formatted = telemHist.history.map((h) => ({
          time: formatAlertTime(h.timestamp),
          cpu: safeNumber(h.cpu_percent, 0),
          memory: safeNumber(h.memory_percent, 0),
        }));
        setTelemetryHistory(formatted);
      }
      setFimStatus(fStatus);
      setFimEvents(fEventsRes?.events || []);
    } catch (err) {
      setError(err.message || 'Failed to load host security data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, [loadData]);

  // Real-time socket event updates
  useSocketEvent('host_status', (data) => {
    if (data) setHostStatus(data);
  });

  useSocketEvent('host_telemetry', (data) => {
    if (!data) return;
    setHostTelemetry(data);
    const nowStr = new Date(Number(data.timestamp || Date.now() / 1000) * 1000).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
    setTelemetryHistory((prev) => {
      const updated = [
        ...prev,
        {
          time: nowStr,
          cpu: safeNumber(data.cpu_percent, 0),
          memory: safeNumber(data.memory_percent, 0),
        },
      ];
      return updated.length > 30 ? updated.slice(-30) : updated;
    });
  });

  useSocketEvent('fim_status', (data) => {
    if (data) setFimStatus(data);
  });

  useSocketEvent('host_security_event', () => {
    loadData();
  });

  const handleConfirmRebaseline = async () => {
    setShowRebaselineConfirm(false);
    setRebaselining(true);
    setRebaselineMsg(null);
    try {
      const res = await triggerFimRebaseline();
      if (res?.success) {
        setRebaselineMsg({ type: 'success', text: 'Baseline successfully updated and persisted.' });
        const [fStatus, fEventsRes] = await Promise.all([
          fetchFimStatus(),
          fetchFimEvents({ limit: 50 }),
        ]);
        setFimStatus(fStatus);
        setFimEvents(fEventsRes?.events || []);
      } else {
        setRebaselineMsg({ type: 'error', text: res?.error || 'Re-baseline failed' });
      }
    } catch (err) {
      setRebaselineMsg({ type: 'error', text: err.message || 'Failed to trigger rebaseline' });
    } finally {
      setRebaselining(false);
    }
  };

  if (loading && !hostStatus && !fimStatus) {
    return <LoadingState message="Loading Host Security subsystem..." />;
  }

  if (error && !hostStatus && !fimStatus) {
    return <ErrorState message={error} onRetry={loadData} />;
  }

  const sshDetector = hostStatus?.components?.ssh_detector || {};
  const procMonitor = hostStatus?.components?.process_monitor || {};
  const isFimActive = fimStatus?.enabled && fimStatus?.baseline_ready;

  // Semantic FIM Badge
  const fimBadgeText = !fimStatus
    ? 'CHECKING'
    : !fimStatus.enabled
    ? 'DISABLED'
    : !fimStatus.baseline_ready
    ? 'INITIALIZING'
    : (fimStatus.changed_count || 0) > 0
    ? 'ALTERED'
    : 'VERIFIED';

  const fimBadgeClass = !fimStatus
    ? 'badge-warning'
    : !fimStatus.enabled
    ? 'badge-info'
    : !fimStatus.baseline_ready
    ? 'badge-warning'
    : (fimStatus.changed_count || 0) > 0
    ? 'badge-danger'
    : 'badge-success';

  // Semantic SSH Badge
  const sshBadgeText = !sshDetector.status
    ? 'STANDBY'
    : (sshDetector.total_brute_force_detected || 0) > 0
    ? 'ATTACKS DETECTED'
    : sshDetector.status === 'RUNNING'
    ? 'NORMAL'
    : sshDetector.status;

  const sshBadgeClass = !sshDetector.status
    ? 'badge-info'
    : (sshDetector.total_brute_force_detected || 0) > 0
    ? 'badge-critical'
    : sshDetector.status === 'RUNNING'
    ? 'badge-success'
    : 'badge-warning';

  return (
    <div className="page-container">
      <PageHeader
        title="Host Security & Integrity (HIDS)"
        subtitle="Host-level intrusion detection, SSH brute-force defense, process monitoring, and cryptographic File Integrity Monitoring"
        actions={
          <button className="btn-refresh" onClick={loadData} title="Refresh Host Telemetry">
            <RotateCcw size={14} /> Refresh
          </button>
        }
      />

      {/* KPI Cards Row */}
      <div className="metric-cards-grid">
        <MetricCard
          title="Monitored Files"
          value={formatNumber(fimStatus?.baseline_file_count, 0, '—')}
          subtext={`${formatNumber(fimStatus?.monitored_path_count, 0, '0')} directory paths`}
          icon={FileText}
          badge={<StatusBadge status={isFimActive ? 'HEALTHY' : 'DISABLED'} text={isFimActive ? 'FIM ACTIVE' : 'FIM OFF'} />}
        />
        <MetricCard
          title="SSH Auth Failures"
          value={formatNumber(sshDetector.total_failures, 0, '0')}
          subtext={`${formatNumber(sshDetector.total_brute_force_detected, 0, '0')} brute-force alerts`}
          icon={Terminal}
          badge={<span className={`badge ${sshBadgeClass}`}>{sshBadgeText}</span>}
        />
        <MetricCard
          title="Suspicious Processes"
          value={formatNumber(procMonitor.suspicious_processes_detected, 0, '0')}
          subtext={`${formatNumber(procMonitor.visible_processes, 0, '0')} total visible PIDs`}
          icon={ShieldAlert}
          badge={
            (procMonitor.suspicious_processes_detected || 0) > 0 ? (
              <span className="badge badge-critical">ACTION REQ</span>
            ) : procMonitor.status === 'RUNNING' ? (
              <span className="badge badge-success">CLEAN</span>
            ) : (
              <span className="badge badge-info">STANDBY</span>
            )
          }
        />
        <MetricCard
          title="Integrity Alterations"
          value={formatNumber(fimStatus?.changed_count, 0, '0')}
          subtext={`${formatNumber(fimStatus?.missing_count, 0, '0')} deletions recorded`}
          icon={AlertTriangle}
          badge={<span className={`badge ${fimBadgeClass}`}>{fimBadgeText}</span>}
        />
      </div>

      {/* Host Telemetry & Resource Trends */}
      {hostTelemetry && (
        <DashboardCard title="Host System Resources & Utilization History" icon={Cpu}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
            {/* Real-time Time Series Chart */}
            <div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '8px', fontWeight: 600 }}>
                CPU & Memory Utilization History (%)
              </div>
              {telemetryHistory.length > 0 ? (
                <div style={{ height: '180px', width: '100%' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={telemetryHistory} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                      <defs>
                        <linearGradient id="hostCpuGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0} />
                        </linearGradient>
                        <linearGradient id="hostMemGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                      <YAxis stroke="#64748b" fontSize={10} tickLine={false} domain={[0, 100]} width={35} tickFormatter={(v) => `${v}%`} />
                      <Tooltip
                        contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                        formatter={(val, name) => [`${val}%`, name]}
                      />
                      <Area type="monotone" dataKey="cpu" stroke="#38bdf8" strokeWidth={2} fillOpacity={1} fill="url(#hostCpuGrad)" name="CPU %" />
                      <Area type="monotone" dataKey="memory" stroke="#10b981" strokeWidth={2} fillOpacity={1} fill="url(#hostMemGrad)" name="RAM %" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <LoadingState message="Collecting resource samples..." compact />
              )}
            </div>

            {/* Instantaneous Host Performance Breakdown */}
            <div className="telemetry-card-container">
              <div className="resource-gauges">
                {/* CPU Gauge */}
                <div className="resource-gauge-item">
                  <div className="gauge-header">
                    <span>Current CPU</span>
                    <span className="gauge-value">{formatPercent(hostTelemetry.cpu_percent, 1)}</span>
                  </div>
                  <div className="gauge-track">
                    <div
                      className={`gauge-fill cpu ${safeNumber(hostTelemetry.cpu_percent) > 90 ? 'danger' : safeNumber(hostTelemetry.cpu_percent) > 75 ? 'warning' : ''}`}
                      style={{ width: `${Math.min(100, Math.max(0, safeNumber(hostTelemetry.cpu_percent)))}%` }}
                    />
                  </div>
                </div>

                {/* RAM Gauge */}
                <div className="resource-gauge-item">
                  <div className="gauge-header">
                    <span>Current RAM</span>
                    <span className="gauge-value">
                      {formatPercent(hostTelemetry.memory_percent, 1)} ({formatBytes(hostTelemetry.memory_used_bytes)} used)
                    </span>
                  </div>
                  <div className="gauge-track">
                    <div
                      className={`gauge-fill mem ${safeNumber(hostTelemetry.memory_percent) > 90 ? 'danger' : safeNumber(hostTelemetry.memory_percent) > 80 ? 'warning' : ''}`}
                      style={{ width: `${Math.min(100, Math.max(0, safeNumber(hostTelemetry.memory_percent)))}%` }}
                    />
                  </div>
                </div>

                {/* Disk Gauge */}
                <div className="resource-gauge-item">
                  <div className="gauge-header">
                    <span>Root Disk</span>
                    <span className="gauge-value">
                      {formatPercent(hostTelemetry.disk_percent, 1)} ({formatBytes(hostTelemetry.disk_used_bytes)} used)
                    </span>
                  </div>
                  <div className="gauge-track">
                    <div
                      className={`gauge-fill disk ${safeNumber(hostTelemetry.disk_percent) > 90 ? 'danger' : safeNumber(hostTelemetry.disk_percent) > 80 ? 'warning' : ''}`}
                      style={{ width: `${Math.min(100, Math.max(0, safeNumber(hostTelemetry.disk_percent)))}%` }}
                    />
                  </div>
                </div>
              </div>

              <div className="telemetry-subgrid">
                <div className="telemetry-mini-stat">
                  <span className="mini-stat-label">OS Load Averages (1m, 5m, 15m)</span>
                  <span className="mini-stat-val">
                    {hostTelemetry.load_1 ?? 0} / {hostTelemetry.load_5 ?? 0} / {hostTelemetry.load_15 ?? 0}
                  </span>
                </div>
                <div className="telemetry-mini-stat">
                  <span className="mini-stat-label">Host Network I/O Rate</span>
                  <span className="mini-stat-val" style={{ fontSize: '0.75rem' }}>
                    ↑ {formatBytes(hostTelemetry.host_tx_bps)}/s | ↓ {formatBytes(hostTelemetry.host_rx_bps)}/s
                  </span>
                </div>
              </div>
            </div>
          </div>
        </DashboardCard>
      )}

      {/* Host Intrusion Detection: SSH & Process Monitor Grid */}
      <div className="dashboard-grid">
        {/* SSH Detection Card */}
        <DashboardCard title="SSH Authentication & Brute-Force Monitor" icon={Terminal}>
          <div className="host-sec-container">
            <div className="host-section-block">
              <div className="host-block-title">
                <span>SSH Daemon Tracker</span>
                <span className={`badge ${
                  sshDetector.status === 'RUNNING' ? 'badge-success' :
                  sshDetector.status === 'NOT_FOUND' ? 'badge-warning' :
                  sshDetector.status === 'PERMISSION_DENIED' ? 'badge-danger' : 'badge-neutral'
                }`}>
                  {sshDetector.status || 'UNKNOWN'}
                </span>
              </div>
              <div className="host-meta-row">
                <span className="meta-label">Monitored Auth Log:</span>
                <span className="meta-val">{sshDetector.log_file || 'auto (/var/log/auth.log)'}</span>
              </div>
              <div className="host-meta-row">
                <span className="meta-label">Brute-Force Threshold:</span>
                <span className="meta-val">
                  {sshDetector.threshold_failures || 5} failures / {sshDetector.window_seconds || 120}s
                </span>
              </div>
              <div className="host-meta-row">
                <span className="meta-label">Current Tracked Attacker IPs:</span>
                <span className="meta-val">{formatNumber(sshDetector.tracked_ips_count, 0, '0')}</span>
              </div>
            </div>

            <div className="host-stats-row">
              <div className="host-stat-box">
                <span className="stat-title">Total Failed Logins</span>
                <span className="stat-num">{formatNumber(sshDetector.total_failures, 0, '0')}</span>
              </div>
              <div className="host-stat-box">
                <span className="stat-title">Brute-Force Alerts</span>
                <span className="stat-num" style={{ color: (sshDetector.total_brute_force_detected || 0) > 0 ? '#f87171' : '#f8fafc' }}>
                  {formatNumber(sshDetector.total_brute_force_detected, 0, '0')}
                </span>
              </div>
            </div>
          </div>
        </DashboardCard>

        {/* Process Monitor Card */}
        <DashboardCard title="Process Integrity Observer" icon={Cpu}>
          <div className="host-sec-container">
            <div className="host-section-block">
              <div className="host-block-title">
                <span>Process Observer Engine</span>
                <span className={`badge ${
                  procMonitor.status === 'RUNNING' ? 'badge-success' :
                  procMonitor.status === 'PERMISSION_DENIED' ? 'badge-danger' : 'badge-neutral'
                }`}>
                  {procMonitor.status || 'UNKNOWN'}
                </span>
              </div>
              <div className="host-meta-row">
                <span className="meta-label">Observation Mechanism:</span>
                <span className="meta-val">Linux /proc pseudo-filesystem + psutil</span>
              </div>
              <div className="host-meta-row">
                <span className="meta-label">Baseline Established:</span>
                <span className="meta-val">{procMonitor.baseline_established ? 'YES (Active)' : 'Initializing'}</span>
              </div>
              <div className="host-meta-row">
                <span className="meta-label">Inspection Interval:</span>
                <span className="meta-val">{procMonitor.interval_seconds || 5.0}s</span>
              </div>
            </div>

            <div className="host-stats-row">
              <div className="host-stat-box">
                <span className="stat-title">Visible Processes</span>
                <span className="stat-num">{formatNumber(procMonitor.visible_processes, 0, '0')}</span>
              </div>
              <div className="host-stat-box">
                <span className="stat-title">Suspicious Invocations</span>
                <span className="stat-num" style={{ color: (procMonitor.suspicious_processes_detected || 0) > 0 ? '#f87171' : '#f8fafc' }}>
                  {formatNumber(procMonitor.suspicious_processes_detected, 0, '0')}
                </span>
              </div>
            </div>
          </div>
        </DashboardCard>
      </div>

      {/* File Integrity Monitoring (FIM) */}
      <DashboardCard
        title="File Integrity Monitoring (FIM)"
        icon={FileText}
        headerRight={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
              Last scan: {fimStatus?.last_scan_timestamp ? formatAlertTime(fimStatus.last_scan_timestamp) : 'Pending'}
            </span>
            <button
              className="btn-refresh"
              style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem', borderColor: 'var(--accent-blue)', color: 'var(--accent-blue)' }}
              onClick={() => setShowRebaselineConfirm(true)}
              disabled={rebaselining}
              title="Rebuild Cryptographic Baseline"
            >
              <CheckCircle2 size={13} /> {rebaselining ? 'Re-baselining...' : 'Re-baseline All'}
            </button>
          </div>
        }
      >
        {/* Rebaseline Confirmation Banner */}
        {showRebaselineConfirm && (
          <div className="safety-banner warning" style={{ marginBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <AlertTriangle size={16} color="#f59e0b" />
              <span>
                Re-establish cryptographic baseline? Current SHA-256 hashes will be saved as the trusted reference state.
              </span>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                className="btn btn-primary"
                style={{ padding: '3px 10px', fontSize: '0.74rem' }}
                onClick={handleConfirmRebaseline}
              >
                Confirm Re-baseline
              </button>
              <button
                className="btn btn-secondary"
                style={{ padding: '3px 10px', fontSize: '0.74rem' }}
                onClick={() => setShowRebaselineConfirm(false)}
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {rebaselineMsg && (
          <div style={{
            margin: '0.5rem 0',
            padding: '0.5rem 0.75rem',
            borderRadius: '4px',
            fontSize: '0.75rem',
            background: rebaselineMsg.type === 'success' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
            border: `1px solid ${rebaselineMsg.type === 'success' ? '#10b981' : '#ef4444'}`,
            color: rebaselineMsg.type === 'success' ? '#86efac' : '#fca5a5',
          }}>
            {rebaselineMsg.text}
          </div>
        )}

        {!fimStatus ? (
          <EmptyState message="Waiting for File Integrity Monitoring status..." icon={FileText} />
        ) : (
          <div className="fim-container">
            {/* Metric stats strip */}
            <div className="fim-stats-grid">
              <div className="fim-stat-card">
                <div className="fim-stat-label">Engine Status</div>
                <div className="fim-stat-value">
                  <span className={`badge ${fimStatus.enabled ? 'badge-success' : 'badge-neutral'}`}>
                    {fimStatus.enabled ? 'ACTIVE' : 'DISABLED'}
                  </span>
                </div>
                <div className="fim-stat-sub">
                  {fimStatus.baseline_ready ? 'Baseline Verified' : 'Initializing'}
                </div>
              </div>

              <div className="fim-stat-card">
                <div className="fim-stat-label">Monitored Files</div>
                <div className="fim-stat-value">{formatNumber(fimStatus.baseline_file_count, 0, '0')}</div>
                <div className="fim-stat-sub">{formatNumber(fimStatus.monitored_path_count, 0, '0')} target path(s)</div>
              </div>

              <div className="fim-stat-card">
                <div className="fim-stat-label">Modified Files</div>
                <div className="fim-stat-value" style={{ color: (fimStatus.changed_count || 0) > 0 ? '#f87171' : '#f8fafc' }}>
                  {formatNumber(fimStatus.changed_count, 0, '0')}
                </div>
                <div className="fim-stat-sub">SHA-256 hash mismatches</div>
              </div>

              <div className="fim-stat-card">
                <div className="fim-stat-label">Added Files</div>
                <div className="fim-stat-value">{formatNumber(fimStatus.added_count, 0, '0')}</div>
                <div className="fim-stat-sub">New files detected</div>
              </div>

              <div className="fim-stat-card">
                <div className="fim-stat-label">Missing Files</div>
                <div className="fim-stat-value" style={{ color: (fimStatus.missing_count || 0) > 0 ? '#fbbf24' : '#f8fafc' }}>
                  {formatNumber(fimStatus.missing_count, 0, '0')}
                </div>
                <div className="fim-stat-sub">Deleted system files</div>
              </div>
            </div>

            {/* FIM Monitored Paths List */}
            <div className="fim-paths-section" style={{ marginTop: '1rem' }}>
              <div className="fim-section-title">
                <span>Configured System File Targets</span>
                <span style={{ fontSize: '0.7rem', color: '#94a3b8' }}>
                  SHA-256 Chunked Hashing (Max {formatBytes(fimStatus.max_file_size || 10485760)})
                </span>
              </div>
              <div className="fim-paths-tags">
                {(fimStatus.monitored_paths || ['/etc/passwd', '/etc/group', '/etc/ssh/sshd_config']).map((p, idx) => (
                  <span key={idx} className="fim-path-pill">
                    <code>{p}</code>
                  </span>
                ))}
              </div>
            </div>

            {/* FIM Audit Table */}
            <div className="fim-events-section" style={{ marginTop: '1rem' }}>
              <div className="fim-section-title">
                <span>Integrity Deviation Audit Trail</span>
                <span style={{ fontSize: '0.7rem', color: '#94a3b8' }}>
                  {fimEvents.length} deviation events recorded
                </span>
              </div>

              <div style={{ overflowX: 'auto', maxHeight: '250px' }}>
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>File Target Path</th>
                      <th>Alteration Type</th>
                      <th>Severity</th>
                      <th>Cryptographic Evidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fimEvents.length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-muted)' }}>
                          No integrity deviations recorded. Monitored files match expected baselines.
                        </td>
                      </tr>
                    ) : (
                      fimEvents.slice(0, 15).map((ev, idx) => {
                        const evData = typeof ev.evidence === 'object' ? ev.evidence : {};
                        const prevHash = evData.previous_sha256 ? `${evData.previous_sha256.substring(0, 12)}...` : '-';
                        const currHash = evData.current_sha256 ? `${evData.current_sha256.substring(0, 12)}...` : '-';
                        return (
                          <tr key={ev.event_id || idx}>
                            <td style={{ color: '#94a3b8', fontSize: '0.7rem' }}>{formatAlertTime(ev.timestamp)}</td>
                            <td>
                              <code style={{ color: '#f8fafc', fontWeight: 500 }}>
                                {evData.path || ev.description}
                              </code>
                            </td>
                            <td>
                              <span className={`badge ${
                                ev.detection_type === 'FILE_MODIFIED' ? 'badge-danger' :
                                ev.detection_type === 'FILE_REPLACED' ? 'badge-danger' :
                                ev.detection_type === 'FILE_DELETED' ? 'badge-warning' :
                                ev.detection_type === 'FILE_CREATED' ? 'badge-info' : 'badge-neutral'
                              }`}>
                                {ev.detection_type}
                              </span>
                            </td>
                            <td>
                              <span className={getRiskBadgeClass(ev.severity)} style={{ fontSize: '0.65rem' }}>
                                {ev.severity}
                              </span>
                            </td>
                            <td style={{ fontSize: '0.7rem', color: '#cbd5e1' }}>
                              {ev.detection_type === 'FILE_MODIFIED' && (
                                <span>Hash: <code style={{ color: '#fca5a5' }}>{prevHash}</code> &rarr; <code style={{ color: '#86efac' }}>{currHash}</code></span>
                              )}
                              {ev.detection_type === 'FILE_REPLACED' && (
                                <span>Inode: {evData.previous_inode} &rarr; {evData.current_inode}</span>
                              )}
                              {ev.detection_type === 'FILE_METADATA_CHANGED' && (
                                <span>Mode: {evData.previous_mode} &rarr; {evData.current_mode}</span>
                              )}
                              {ev.detection_type === 'FILE_CREATED' && (
                                <span>New file (size: {formatBytes(evData.size)})</span>
                              )}
                              {ev.detection_type === 'FILE_DELETED' && (
                                <span style={{ color: '#fca5a5' }}>File removed from disk</span>
                              )}
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </DashboardCard>
    </div>
  );
}
