import React, { useState, useEffect, useCallback } from 'react';
import {
  Terminal,
  FileText,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Cpu,
  ShieldAlert,
  HardDrive,
  Activity,
  Layers,
} from 'lucide-react';
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
  fetchFimStatus,
  fetchFimEvents,
  triggerFimRebaseline,
} from '../services/api';
import {
  formatBytes,
  formatNumber,
  formatAlertTime,
  formatFullTime,
  getRiskBadgeClass,
} from '../utils/formatters';

export default function HostSecurity() {
  const [hostStatus, setHostStatus] = useState(null);
  const [hostTelemetry, setHostTelemetry] = useState(null);
  const [fimStatus, setFimStatus] = useState(null);
  const [fimEvents, setFimEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [rebaselining, setRebaselining] = useState(false);
  const [rebaselineMsg, setRebaselineMsg] = useState(null);

  const loadData = useCallback(async () => {
    try {
      setError(null);
      const [hStatus, telem, fStatus, fEventsRes] = await Promise.all([
        fetchHostStatus(),
        fetchTelemetryCurrent(),
        fetchFimStatus(),
        fetchFimEvents({ limit: 50 }),
      ]);
      setHostStatus(hStatus);
      setHostTelemetry(telem);
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
    if (data) setHostTelemetry(data);
  });

  useSocketEvent('fim_status', (data) => {
    if (data) setFimStatus(data);
  });

  useSocketEvent('host_security_event', () => {
    loadData();
  });

  const handleRebaseline = async () => {
    if (!window.confirm("Re-establish baseline for all monitored paths? This will update expected cryptographic hashes to their current state.")) {
      return;
    }
    setRebaselining(true);
    setRebaselineMsg(null);
    try {
      const res = await triggerFimRebaseline();
      if (res?.success) {
        setRebaselineMsg({ type: 'success', text: 'Baseline successfully updated.' });
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

  const sshDetector = hostStatus?.ssh_detector || {};
  const procMonitor = hostStatus?.process_monitor || {};
  const isFimActive = fimStatus?.enabled ?? false;

  return (
    <div className="page-container">
      <PageHeader
        title="Host Security & Integrity (HIDS)"
        subtitle="Host-level intrusion detection, SSH brute-force defense, process monitoring, and File Integrity Monitoring"
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
          value={formatNumber(fimStatus?.baseline_file_count ?? 0)}
          subtext={`${fimStatus?.monitored_path_count ?? 0} directory paths`}
          icon={FileText}
          badge={<StatusBadge status={isFimActive ? 'HEALTHY' : 'DISABLED'} text={isFimActive ? 'FIM ACTIVE' : 'FIM OFF'} />}
        />
        <MetricCard
          title="SSH Auth Failures"
          value={formatNumber(sshDetector.total_failures ?? 0)}
          subtext={`${sshDetector.total_brute_force_detected ?? 0} brute-force alerts`}
          icon={Terminal}
          badge={
            (sshDetector.total_brute_force_detected ?? 0) > 0 ? (
              <span className="badge badge-critical">ATTACKS DETECTED</span>
            ) : (
              <span className="badge badge-success">NORMAL</span>
            )
          }
        />
        <MetricCard
          title="Suspicious Processes"
          value={formatNumber(procMonitor.suspicious_processes_detected ?? 0)}
          subtext={`${procMonitor.visible_processes ?? 0} total visible PIDs`}
          icon={ShieldAlert}
          badge={
            (procMonitor.suspicious_processes_detected ?? 0) > 0 ? (
              <span className="badge badge-critical">ACTION REQ</span>
            ) : (
              <span className="badge badge-success">CLEAN</span>
            )
          }
        />
        <MetricCard
          title="Integrity Alterations"
          value={formatNumber(fimStatus?.changed_count ?? 0)}
          subtext={`${fimStatus?.missing_count ?? 0} deletions recorded`}
          icon={AlertTriangle}
          badge={
            (fimStatus?.changed_count ?? 0) > 0 ? (
              <span className="badge badge-danger">ALTERED</span>
            ) : (
              <span className="badge badge-success">VERIFIED</span>
            )
          }
        />
      </div>

      {/* Host Telemetry & Resource Utilization */}
      {hostTelemetry && (
        <DashboardCard title="Host System Resources & Performance" icon={Cpu}>
          <div className="telemetry-card-container">
            <div className="resource-gauges">
              {/* CPU Gauge */}
              <div className="resource-gauge-item">
                <div className="gauge-header">
                  <span>CPU Utilization</span>
                  <span className="gauge-value">{Number(hostTelemetry.cpu_percent || 0).toFixed(1)}%</span>
                </div>
                <div className="gauge-track">
                  <div
                    className={`gauge-fill cpu ${hostTelemetry.cpu_percent > 90 ? 'danger' : hostTelemetry.cpu_percent > 75 ? 'warning' : ''}`}
                    style={{ width: `${Math.min(100, Math.max(0, hostTelemetry.cpu_percent || 0))}%` }}
                  />
                </div>
              </div>

              {/* RAM Gauge */}
              <div className="resource-gauge-item">
                <div className="gauge-header">
                  <span>RAM Memory</span>
                  <span className="gauge-value">
                    {Number(hostTelemetry.memory_percent || 0).toFixed(1)}% ({formatBytes(hostTelemetry.memory_used_bytes)} / {formatBytes((hostTelemetry.memory_used_bytes || 0) + (hostTelemetry.memory_available_bytes || 0))})
                  </span>
                </div>
                <div className="gauge-track">
                  <div
                    className={`gauge-fill mem ${hostTelemetry.memory_percent > 90 ? 'danger' : hostTelemetry.memory_percent > 80 ? 'warning' : ''}`}
                    style={{ width: `${Math.min(100, Math.max(0, hostTelemetry.memory_percent || 0))}%` }}
                  />
                </div>
              </div>

              {/* Disk Gauge */}
              <div className="resource-gauge-item">
                <div className="gauge-header">
                  <span>Disk Space</span>
                  <span className="gauge-value">
                    {Number(hostTelemetry.disk_percent || 0).toFixed(1)}% ({formatBytes(hostTelemetry.disk_used_bytes)} used)
                  </span>
                </div>
                <div className="gauge-track">
                  <div
                    className={`gauge-fill disk ${hostTelemetry.disk_percent > 90 ? 'danger' : hostTelemetry.disk_percent > 80 ? 'warning' : ''}`}
                    style={{ width: `${Math.min(100, Math.max(0, hostTelemetry.disk_percent || 0))}%` }}
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
                <span className="mini-stat-label">Host Network Rate</span>
                <span className="mini-stat-val" style={{ fontSize: '0.75rem' }}>
                  ↑ {formatBytes(hostTelemetry.host_tx_bps)}/s | ↓ {formatBytes(hostTelemetry.host_rx_bps)}/s
                </span>
              </div>
            </div>
          </div>
        </DashboardCard>
      )}

      {/* Host Intrusion Detection: SSH & Process Monitor Grid */}
      <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr', gap: '1rem', marginTop: '1rem' }}>
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
                  {sshDetector.status || 'STANDBY'}
                </span>
              </div>
              <div className="host-stat-row">
                <span>Auth Log Source:</span>
                <span className="host-stat-val" style={{ fontSize: '0.7rem' }}>
                  {sshDetector.log_path ? sshDetector.log_path.split('/').slice(-2).join('/') : 'Auto-detect'}
                </span>
              </div>
              <div className="host-stat-row">
                <span>Auth Failures:</span>
                <span className="host-stat-val">{sshDetector.total_failures || 0}</span>
              </div>
              <div className="host-stat-row">
                <span>Brute-Force Detections:</span>
                <span className="host-stat-val" style={{ color: (sshDetector.total_brute_force_detected || 0) > 0 ? 'var(--status-red)' : 'inherit' }}>
                  {sshDetector.total_brute_force_detected || 0}
                </span>
              </div>
              <div className="host-stat-row">
                <span>Tracked Attacker IPs:</span>
                <span className="host-stat-val">{sshDetector.tracked_sources_count || 0}</span>
              </div>
            </div>
          </div>
        </DashboardCard>

        {/* Process Monitor Card */}
        <DashboardCard title="Process Integrity Monitor" icon={Activity}>
          <div className="host-sec-container">
            <div className="host-section-block">
              <div className="host-block-title">
                <span>System Process Scanner</span>
                <span className={`badge ${
                  procMonitor.status === 'RUNNING' ? 'badge-success' : 'badge-neutral'
                }`}>
                  {procMonitor.status || 'STANDBY'}
                </span>
              </div>
              <div className="host-stat-row">
                <span>Baseline Active PIDs:</span>
                <span className="host-stat-val">{procMonitor.baseline_pids_count || 0}</span>
              </div>
              <div className="host-stat-row">
                <span>Periodic Integrity Scans:</span>
                <span className="host-stat-val">{procMonitor.total_scans || 0}</span>
              </div>
              <div className="host-stat-row">
                <span>Suspicious Processes:</span>
                <span className="host-stat-val" style={{ color: (procMonitor.suspicious_processes_detected || 0) > 0 ? 'var(--status-red)' : 'inherit' }}>
                  {procMonitor.suspicious_processes_detected || 0}
                </span>
              </div>
              <div className="host-stat-row">
                <span>Visible System PIDs:</span>
                <span className="host-stat-val">{procMonitor.visible_processes || 0}</span>
              </div>
            </div>
          </div>
        </DashboardCard>
      </div>

      {/* File Integrity Monitoring (FIM) */}
      <div style={{ marginTop: '1rem' }}>
        <DashboardCard
          title="File Integrity Monitoring (FIM)"
          icon={FileText}
          actions={
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <button
                className="btn-refresh"
                style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem', borderColor: 'var(--accent-blue)', color: 'var(--accent-blue)' }}
                onClick={handleRebaseline}
                disabled={rebaselining}
                title="Rebuild Cryptographic Baseline"
              >
                <CheckCircle2 size={13} /> {rebaselining ? 'Re-baselining...' : 'Re-baseline All'}
              </button>
            </div>
          }
        >
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
                  <div className="fim-stat-value">{fimStatus.baseline_file_count ?? 0}</div>
                  <div className="fim-stat-sub">{fimStatus.monitored_path_count ?? 0} target path(s)</div>
                </div>

                <div className="fim-stat-card">
                  <div className="fim-stat-label">Integrity Alterations</div>
                  <div className="fim-stat-value" style={{ color: (fimStatus.changed_count || 0) > 0 ? 'var(--status-red)' : 'var(--status-green)' }}>
                    {fimStatus.changed_count ?? 0}
                  </div>
                  <div className="fim-stat-sub">SHA-256 diffs</div>
                </div>

                <div className="fim-stat-card">
                  <div className="fim-stat-label">Missing Targets</div>
                  <div className="fim-stat-value" style={{ color: (fimStatus.missing_count || 0) > 0 ? 'var(--status-amber)' : 'inherit' }}>
                    {fimStatus.missing_count ?? 0}
                  </div>
                  <div className="fim-stat-sub">File deletions</div>
                </div>

                <div className="fim-stat-card">
                  <div className="fim-stat-label">Unreadable</div>
                  <div className="fim-stat-value" style={{ color: (fimStatus.unreadable_count || 0) > 0 ? 'var(--status-amber)' : 'inherit' }}>
                    {fimStatus.unreadable_count ?? 0}
                  </div>
                  <div className="fim-stat-sub">Permissions</div>
                </div>
              </div>

              {/* Scan telemetry banner */}
              <div className="fim-meta-banner">
                <span><strong>Scan Interval:</strong> {fimStatus.interval_seconds || 30}s</span>
                <span><strong>Last Scan:</strong> {fimStatus.last_scan_at ? formatFullTime(fimStatus.last_scan_at) : 'In progress...'}</span>
                <span><strong>Last Alert:</strong> {fimStatus.last_change_at ? formatFullTime(fimStatus.last_change_at) : 'None'}</span>
                {fimStatus.last_error && <span style={{ color: 'var(--status-red)' }}><strong>Error:</strong> {fimStatus.last_error}</span>}
              </div>

              {/* Recent FIM Events Table */}
              <div className="fim-events-wrapper">
                <div className="fim-events-title">
                  <span>Recent Integrity Events</span>
                  <span style={{ color: '#94a3b8', fontSize: '0.7rem' }}>Showing latest recorded file events</span>
                </div>
                <div className="history-table-container">
                  <table className="history-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Path</th>
                        <th>Change Type</th>
                        <th>Severity</th>
                        <th>Fingerprint / Metadata</th>
                      </tr>
                    </thead>
                    <tbody>
                      {fimEvents.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="history-empty-row">
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
                              <td style={{ fontFamily: 'monospace', color: '#f8fafc', fontWeight: 500 }}>
                                {evData.path || ev.description}
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
    </div>
  );
}
