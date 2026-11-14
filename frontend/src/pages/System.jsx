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
  Radio,
} from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { MetricCard } from '../components/common/MetricCard';
import { DashboardCard } from '../components/DashboardCard';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { checkBackendHealth, fetchReadiness, fetchSystemStatus } from '../services/api';
import { socket } from '../services/socket';
import { formatUptime } from '../utils/formatters';

export default function System() {
  const [health, setHealth] = useState(null);
  const [readiness, setReadiness] = useState(null);
  const [systemStatus, setSystemStatus] = useState(null);
  const [socketConnected, setSocketConnected] = useState(socket?.connected || false);
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

    const onConnect = () => setSocketConnected(true);
    const onDisconnect = () => setSocketConnected(false);
    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    setSocketConnected(socket.connected || false);

    return () => {
      clearInterval(interval);
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
    };
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
  const firewallConfigured = Boolean(systemStatus?.firewall) && (
    systemStatus.firewall.enabled ?? systemStatus.firewall.mode !== 'disabled'
  );

  // Database state
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
        title="System Status"
        subtitle="Runtime subsystem health, background workers, and service connectivity"
        actions={
          <button className="btn-refresh" onClick={loadData} title="Run Diagnostic Probes">
            <RotateCcw size={14} /> Refresh
          </button>
        }
      />

      {/* Notice Banners */}
      {is429 && (
        <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid var(--status-red)', borderRadius: '6px', padding: '10px 14px', marginBottom: '1rem', fontSize: '0.85rem', color: '#fca5a5', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <AlertTriangle size={18} color="var(--status-red)" />
          <span><strong>HTTP 429 Throttling:</strong> API request rate limit reached. Temporary request backoff in effect.</span>
        </div>
      )}

      {isConnected && readiness && !isReady && !is429 && (
        <div style={{ background: 'rgba(245, 158, 11, 0.15)', border: '1px solid var(--status-yellow)', borderRadius: '6px', padding: '10px 14px', marginBottom: '1rem', fontSize: '0.85rem', color: '#fcd34d', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <AlertTriangle size={18} color="var(--status-yellow)" />
          <span><strong>Degraded Health (HTTP 503):</strong> One or more subsystem workers are offline or degraded.</span>
        </div>
      )}

      {firewallConfigured && !systemStatus.firewall.dry_run && !systemStatus.firewall.capable && (
        <div style={{ background: 'rgba(239, 68, 68, 0.12)', border: '1px solid var(--status-red)', borderRadius: '6px', padding: '10px 14px', marginBottom: '1rem', fontSize: '0.85rem', color: '#fca5a5' }}>
          <strong>Firewall unavailable:</strong> {systemStatus.firewall.reason || 'The iptables capability check failed.'}
        </div>
      )}

      {/* Consolidated Runtime Service Metric Cards */}
      <div className="metric-cards-grid">
        <MetricCard
          title="Detection Engine"
          value={!isConnected ? 'OFFLINE' : isReady ? 'READY' : readiness ? 'DEGRADED' : 'CHECKING'}
          subtext={isConnected ? 'Readiness probe (/api/ready)' : 'Waiting for REST API'}
          icon={CheckCircle2}
        />
        <MetricCard
          title="REST API"
          value={isConnected ? 'LIVE' : 'OFFLINE'}
          subtext={`Uptime: ${formatUptime(appUptime)}`}
          icon={Activity}
        />
        <MetricCard
          title="WebSocket Stream"
          value={socketConnected ? 'ONLINE' : 'OFFLINE'}
          subtext="Real-time event stream"
          icon={Radio}
        />
        <MetricCard
          title="Database"
          value={dbLatencyDisplay}
          subtext="SQLite WAL storage"
          icon={Database}
        />
        <MetricCard
          title="Firewall Netfilter"
          value={!systemStatus?.firewall
            ? isConnected ? 'CHECKING' : 'OFFLINE'
            : !firewallConfigured
            ? 'DISABLED'
            : systemStatus.firewall.dry_run
            ? 'DRY-RUN'
            : systemStatus.firewall.capable
            ? 'LIVE KERNEL'
            : 'UNAVAILABLE'}
          subtext={systemStatus?.firewall?.reason || `Chain: ${systemStatus?.firewall?.chain || 'NETSENTINEL'}`}
          icon={Shield}
        />
      </div>

      {/* Subsystem Worker Lifecycle Matrix */}
      <div style={{ marginTop: '1rem' }}>
        <DashboardCard
          title="Subsystem Background Workers"
          subtitle="Real-time lifecycle state and thread heartbeat for NetSentinel background workers"
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
                    <th>Diagnostics</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(workers).map(([name, w]) => (
                    <tr key={name}>
                      <td style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.85rem' }}>
                        {name.replace(/_/g, ' ')}
                      </td>
                      <td style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                        {w.role || 'Background process'}
                      </td>
                      <td>
                        <span className={`badge ${w.status === 'RUNNING' || w.status === 'ACTIVE' || w.status === 'HEALTHY' ? 'badge-success' : w.status === 'DEGRADED' ? 'badge-warning' : 'badge-neutral'}`}>
                          {w.status || 'UNKNOWN'}
                        </span>
                      </td>
                      <td style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>
                        {w.last_heartbeat_seconds != null ? `${w.last_heartbeat_seconds}s ago` : 'Active'}
                      </td>
                      <td style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', fontFamily: 'monospace' }}>
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

      {/* System Runtime Configuration */}
      <div style={{ marginTop: '1rem' }}>
        <DashboardCard title="Runtime Environment & Parameters" icon={Server}>
          <div className="dashboard-grid">
            <div className="host-section-block">
              <div className="host-block-title">Core Application</div>
              <div className="host-stat-row">
                <span>Version:</span>
                <span className="host-stat-val">v{systemStatus?.application?.version || health?.data?.version || '1.0.0'}</span>
              </div>
              <div className="host-stat-row">
                <span>Environment:</span>
                <span className="host-stat-val">{systemStatus?.application?.environment || (isConnected ? 'Unknown' : 'Unavailable')}</span>
              </div>
              <div className="host-stat-row">
                <span>Process ID:</span>
                <span className="host-stat-val" style={{ fontFamily: 'monospace' }}>{systemStatus?.application?.pid || (isConnected ? 'Unknown' : 'Unavailable')}</span>
              </div>
              <div className="host-stat-row">
                <span>Host Telemetry:</span>
                <span className="host-stat-val">
                  {systemStatus?.telemetry
                    ? systemStatus.telemetry.enabled ? 'Active (psutil)' : 'Disabled'
                    : isConnected ? 'Unknown' : 'Unavailable'}
                </span>
              </div>
            </div>

            <div className="host-section-block">
              <div className="host-block-title">Packet Engine & Interface</div>
              <div className="host-stat-row">
                <span>Capture Interface:</span>
                <span className="host-stat-val" style={{ fontFamily: 'monospace', color: 'var(--accent-cyan)' }}>
                  {systemStatus?.packet_capture?.interface || (isConnected ? 'Auto' : 'Unavailable')}
                </span>
              </div>
              <div className="host-stat-row">
                <span>Capture Status:</span>
                <span className="host-stat-val">{systemStatus?.packet_capture?.status ? systemStatus.packet_capture.status.toUpperCase() : 'UNKNOWN'}</span>
              </div>
              {systemStatus?.packet_capture?.error && (
                <div style={{ marginTop: '6px', marginBottom: '8px', padding: '6px 10px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.25)', borderRadius: '4px', fontSize: '11px', color: 'var(--status-red)', lineHeight: '1.4' }}>
                  {systemStatus.packet_capture.error}
                </div>
              )}
              <div className="host-stat-row">
                <span>Socket Protocol:</span>
                <span className="host-stat-val">AF_PACKET / Raw Ethernet</span>
              </div>
            </div>

            <div className="host-section-block">
              <div className="host-block-title">Detection Engines</div>
              <div className="host-stat-row">
                <span>Signature Rules:</span>
                <span className="host-stat-val" style={{ color: 'var(--status-green)' }}>Active (TCP/UDP/ICMP/ARP)</span>
              </div>
              <div className="host-stat-row">
                <span>Isolation Forest:</span>
                <span className="host-stat-val" style={{ color: 'var(--status-green)' }}>
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
