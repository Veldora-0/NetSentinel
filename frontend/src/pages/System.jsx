import React, { useState, useEffect, useCallback } from 'react';
import {
  Server,
  Activity,
  Database,
  Shield,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Layers,
} from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { MetricCard } from '../components/common/MetricCard';
import { StatusBadge } from '../components/common/StatusBadge';
import { DashboardCard } from '../components/DashboardCard';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { checkBackendHealth, fetchReadiness, fetchSystemStatus } from '../services/api';
import { formatUptime } from '../utils/formatters';

export default function System() {
  const [health, setHealth] = useState(null);
  const [readiness, setReadiness] = useState(null);
  const [systemStatus, setSystemStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadData = useCallback(async () => {
    try {
      setError(null);
      const [h, r, s] = await Promise.all([
        checkBackendHealth(),
        fetchReadiness(),
        fetchSystemStatus(),
      ]);
      setHealth(h);
      setReadiness(r);
      setSystemStatus(s);
    } catch (err) {
      setError(err.message || 'Failed to load system diagnostics');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 8000);
    return () => clearInterval(interval);
  }, [loadData]);

  if (loading && !health && !systemStatus) {
    return <LoadingState message="Probing system health and operational readiness..." />;
  }

  if (error && !health && !systemStatus) {
    return <ErrorState error={error} onRetry={loadData} />;
  }

  const isReady = readiness?.ready === true;
  const isConnected = health?.connected === true;
  const is429 = readiness?.status === 429;

  // Semantically correct database state: UNKNOWN/CHECKING != HEALTHY
  const dbStatus = systemStatus?.database != null
    ? (systemStatus.database.healthy ? 'HEALTHY' : 'OFFLINE')
    : 'CHECKING';
  const dbLatencyDisplay = dbStatus === 'HEALTHY'
    ? `${systemStatus.database.latency_ms ?? '<1'} ms`
    : dbStatus;

  const appUptime = systemStatus?.application?.uptime_seconds;
  const workers = systemStatus?.workers || {};

  return (
    <div className="page-container">
      <PageHeader
        title="System Status & Health Diagnostics"
        subtitle="Runtime operational readiness probes, subsystem worker states, database telemetry, and platform diagnostics"
        actions={
          <button className="btn-refresh" onClick={loadData} title="Run Diagnostic Probes">
            <RotateCcw size={14} /> Refresh Probes
          </button>
        }
      />

      {/* Notice Banners */}
      {is429 && (
        <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', borderRadius: '6px', padding: '10px 14px', marginBottom: '1rem', fontSize: '0.85rem', color: '#fca5a5', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <AlertTriangle size={18} color="#ef4444" />
          <span><strong>HTTP 429 Throttling:</strong> API request rate limit reached. Temporary request backoff in effect.</span>
        </div>
      )}

      {readiness && !isReady && !is429 && (
        <div style={{ background: 'rgba(245, 158, 11, 0.15)', border: '1px solid #f59e0b', borderRadius: '6px', padding: '10px 14px', marginBottom: '1rem', fontSize: '0.85rem', color: '#fcd34d', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <AlertTriangle size={18} color="#f59e0b" />
          <span><strong>Degraded Health (HTTP 503):</strong> One or more required subsystem workers or storage components are offline or degraded.</span>
        </div>
      )}

      {/* KPI Probe Cards */}
      <div className="metric-cards-grid">
        <MetricCard
          title="Readiness Probe (/api/ready)"
          value={isReady ? 'READY (200)' : readiness ? 'DEGRADED (503)' : 'CHECKING'}
          subtext="Kubernetes / Systemd operational gate"
          icon={CheckCircle2}
          badge={<StatusBadge status={isReady ? 'HEALTHY' : readiness ? 'DEGRADED' : 'CHECKING'} text={isReady ? 'READY' : readiness ? 'DEGRADED' : 'CHECKING'} />}
        />
        <MetricCard
          title="Liveness Health (/api/health)"
          value={isConnected ? 'CONNECTED' : 'DISCONNECTED'}
          subtext={`Uptime: ${formatUptime(appUptime)}`}
          icon={Activity}
          badge={<StatusBadge status={isConnected ? 'HEALTHY' : 'FAILED'} text={isConnected ? 'ONLINE' : 'OFFLINE'} />}
        />
        <MetricCard
          title="Database Latency"
          value={dbLatencyDisplay}
          subtext="SQLite WAL durable persistence layer"
          icon={Database}
          badge={<StatusBadge status={dbStatus} text={dbStatus} />}
        />
        <MetricCard
          title="Firewall Netfilter"
          value={systemStatus?.firewall?.capable ? (systemStatus.firewall.dry_run ? 'DRY-RUN' : 'LIVE KERNEL') : (systemStatus?.firewall ? 'DISABLED' : 'CHECKING')}
          subtext={`Chain: ${systemStatus?.firewall?.chain || 'NETSENTINEL'}`}
          icon={Shield}
          badge={
            <span className={`badge ${systemStatus?.firewall?.capable ? (systemStatus.firewall.dry_run ? 'badge-warning' : 'badge-success') : systemStatus?.firewall ? 'badge-info' : 'badge-neutral'}`}>
              {systemStatus?.firewall?.capable ? (systemStatus.firewall.dry_run ? 'DRY-RUN' : 'ACTIVE') : (systemStatus?.firewall ? 'OFF' : 'CHECKING')}
            </span>
          }
        />
      </div>

      {/* Subsystem Worker Lifecycle Matrix */}
      <div style={{ marginTop: '1rem' }}>
        <DashboardCard
          title="Subsystem Background Workers & Health Matrix"
          subtitle="Real-time lifecycle state and thread heartbeat timestamps for all NetSentinel subsystems"
          icon={Layers}
        >
          {Object.keys(workers).length === 0 ? (
            <EmptyState message="No worker state telemetry reported yet." icon={Layers} />
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Subsystem Worker</th>
                    <th>Role / Responsibility</th>
                    <th>Status</th>
                    <th>Last Heartbeat</th>
                    <th>Worker Diagnostics</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(workers).map(([name, w]) => (
                    <tr key={name}>
                      <td style={{ fontWeight: 600, color: '#f8fafc', fontSize: '0.85rem' }}>
                        {name.replace(/_/g, ' ').toUpperCase()}
                      </td>
                      <td style={{ color: '#cbd5e1', fontSize: '0.8rem' }}>
                        {w.role || 'Background operational process'}
                      </td>
                      <td>
                        <StatusBadge status={w.status || 'UNKNOWN'} text={w.status || 'UNKNOWN'} />
                      </td>
                      <td style={{ color: '#94a3b8', fontSize: '0.75rem' }}>
                        {w.last_heartbeat_seconds != null ? `${w.last_heartbeat_seconds}s ago` : 'Active'}
                      </td>
                      <td style={{ color: '#94a3b8', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                        {w.details ? JSON.stringify(w.details) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </DashboardCard>
      </div>

      {/* System Runtime Configuration (Redacted) */}
      <div style={{ marginTop: '1rem' }}>
        <DashboardCard title="Runtime Environment & Parameters" icon={Server}>
          <div className="host-sec-container" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
            <div className="host-section-block">
              <div className="host-block-title">Core Application</div>
              <div className="host-stat-row">
                <span>Version:</span>
                <span className="host-stat-val">v{systemStatus?.application?.version || health?.data?.version || '1.0.0'}</span>
              </div>
              <div className="host-stat-row">
                <span>Environment:</span>
                <span className="host-stat-val">{systemStatus?.application?.environment || 'production'}</span>
              </div>
              <div className="host-stat-row">
                <span>Process ID:</span>
                <span className="host-stat-val" style={{ fontFamily: 'monospace' }}>{systemStatus?.application?.pid || '—'}</span>
              </div>
              <div className="host-stat-row">
                <span>Host Telemetry:</span>
                <span className="host-stat-val">{systemStatus?.telemetry?.enabled ? 'Active (psutil)' : 'Disabled'}</span>
              </div>
            </div>

            <div className="host-section-block">
              <div className="host-block-title">Packet Engine & Interface</div>
              <div className="host-stat-row">
                <span>Capture Interface:</span>
                <span className="host-stat-val" style={{ fontFamily: 'monospace', color: '#38bdf8' }}>
                  {systemStatus?.packet_capture?.interface || 'Auto'}
                </span>
              </div>
              <div className="host-stat-row">
                <span>Capture Status:</span>
                <span className="host-stat-val">{systemStatus?.packet_capture?.status ? systemStatus.packet_capture.status.toUpperCase() : 'UNKNOWN'}</span>
              </div>
              <div className="host-stat-row">
                <span>Socket Protocol:</span>
                <span className="host-stat-val">AF_PACKET / Raw Ethernet</span>
              </div>
            </div>

            <div className="host-section-block">
              <div className="host-block-title">Detection Engines</div>
              <div className="host-stat-row">
                <span>Signature Rules:</span>
                <span className="host-stat-val" style={{ color: '#10b981' }}>Active (TCP/UDP/ICMP/ARP)</span>
              </div>
              <div className="host-stat-row">
                <span>Isolation Forest:</span>
                <span className="host-stat-val" style={{ color: '#10b981' }}>
                  {systemStatus?.ml_detector?.model_ready ? 'Model Ready' : systemStatus?.ml_detector?.collecting_baseline ? 'Collecting Baseline' : 'Active (scikit-learn)'}
                </span>
              </div>
              <div className="host-stat-row">
                <span>Threat Intelligence:</span>
                <span className="host-stat-val">
                  {systemStatus?.threat_intel != null
                    ? (systemStatus.threat_intel.enabled ? 'Active' : 'Standby / Local')
                    : 'UNKNOWN'}
                </span>
              </div>
            </div>
          </div>
        </DashboardCard>
      </div>
    </div>
  );
}
