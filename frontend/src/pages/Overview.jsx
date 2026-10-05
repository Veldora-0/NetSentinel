import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  AlertOctagon,
  Shield,
  ShieldCheck,
  Cpu,
  ArrowRight,
  Server,
  Radio,
  ExternalLink,
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';
import { PageHeader } from '../components/layout/PageHeader';
import { MetricCard } from '../components/common/MetricCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { DashboardCard } from '../components/DashboardCard';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { useSocketEvent } from '../hooks/useSocketEvent';
import {
  fetchReadiness,
  fetchTrafficMetrics,
  fetchSecuritySummary,
  fetchIncidents,
  fetchIncidentStats,
  fetchBlockedIPs,
  fetchRecentRisks,
  fetchTelemetryCurrent,
} from '../services/api';
import {
  formatNumber,
  formatBytes,
  formatRate,
  formatScore,
  formatPercent,
  formatAlertTime,
  getIncidentStatusBadgeClass,
  getRiskBadgeClass,
} from '../utils/formatters';

export function Overview() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // High-level data
  const [readiness, setReadiness] = useState(null);
  const [trafficMetrics, setTrafficMetrics] = useState(null);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [summary, setSummary] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [incidentStats, setIncidentStats] = useState(null);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [recentRisks, setRecentRisks] = useState([]);
  const [telemetry, setTelemetry] = useState(null);

  // Initial load
  const loadOverviewData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [readyRes, trafficRes, sumRes, incRes, statsRes, blockedRes, risksRes, telemRes] =
        await Promise.allSettled([
          fetchReadiness(),
          fetchTrafficMetrics(),
          fetchSecuritySummary(),
          fetchIncidents({ limit: 5 }),
          fetchIncidentStats(),
          fetchBlockedIPs(),
          fetchRecentRisks(5),
          fetchTelemetryCurrent(),
        ]);

      if (readyRes.status === 'fulfilled' && readyRes.value) setReadiness(readyRes.value);
      if (trafficRes.status === 'fulfilled' && trafficRes.value) setTrafficMetrics(trafficRes.value);
      if (sumRes.status === 'fulfilled' && sumRes.value?.summary) setSummary(sumRes.value.summary);
      if (incRes.status === 'fulfilled' && incRes.value?.incidents) setIncidents(incRes.value.incidents);
      if (statsRes.status === 'fulfilled' && statsRes.value?.stats) setIncidentStats(statsRes.value.stats);
      if (blockedRes.status === 'fulfilled' && Array.isArray(blockedRes.value)) setBlockedIPs(blockedRes.value);
      if (risksRes.status === 'fulfilled' && risksRes.value?.assessments) setRecentRisks(risksRes.value.assessments);
      if (telemRes.status === 'fulfilled' && telemRes.value?.telemetry) setTelemetry(telemRes.value.telemetry);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadOverviewData();
  }, []);

  // Real-time socket stream subscriptions
  useSocketEvent('traffic_metrics', (data) => {
    if (!data) return;
    setTrafficMetrics(data);
    const nowStr = new Date(Number(data.timestamp || Date.now() / 1000) * 1000).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
    setTrafficHistory((prev) => {
      const updated = [
        ...prev,
        {
          time: nowStr,
          pps: Number(data.current_pps || 0),
          bps: Number(data.current_bps || 0),
        },
      ];
      return updated.length > 20 ? updated.slice(-20) : updated;
    });
  });

  useSocketEvent('host_telemetry', (data) => {
    if (data) setTelemetry(data);
  });

  useSocketEvent('incident_created', () => {
    fetchIncidents({ limit: 5 }).then((res) => {
      if (res?.incidents) setIncidents(res.incidents);
    });
    fetchIncidentStats().then((res) => {
      if (res?.stats) setIncidentStats(res.stats);
    });
  });

  useSocketEvent('incident_updated', () => {
    fetchIncidents({ limit: 5 }).then((res) => {
      if (res?.incidents) setIncidents(res.incidents);
    });
  });

  useSocketEvent('blocked_ips', (data) => {
    if (Array.isArray(data)) setBlockedIPs(data);
  });

  useSocketEvent('risk_assessment', (data) => {
    if (!data) return;
    setRecentRisks((prev) => [data, ...prev.slice(0, 4)]);
  });

  // Calculate highest current risk score
  const highestRiskScore = recentRisks.length > 0
    ? Math.max(...recentRisks.map((r) => Number(r.risk_score || 0)))
    : 0;

  const highestRiskLevel = recentRisks.length > 0
    ? recentRisks[0]?.risk_level || 'LOW'
    : 'LOW';

  return (
    <div className="overview-page">
      <PageHeader
        title="Security Operations Overview"
        subtitle="Live situational awareness and high-level posture across network and host subsystems"
        actions={
          <div style={{ display: 'flex', gap: '8px' }}>
            <button className="btn btn-secondary" onClick={loadOverviewData}>
              Refresh Posture
            </button>
            <Link to="/incidents" className="btn btn-primary">
              Investigation Workspace
            </Link>
          </div>
        }
      />

      {error && <ErrorState error={error} onRetry={loadOverviewData} />}

      {/* Readiness / Degradation Alert Banner */}
      {readiness && !readiness.ready && (
        <div style={{ background: 'rgba(245, 158, 11, 0.15)', border: '1px solid #f59e0b', borderRadius: '6px', padding: '12px 16px', marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertTriangle size={20} style={{ color: '#f59e0b' }} />
            <span style={{ fontSize: '0.88rem', color: '#fcd34d' }}>
              Operational Warning: One or more background subsystem workers or database are offline (503 Degraded).
            </span>
          </div>
          <Link to="/system" className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: '0.78rem' }}>
            Inspect System Health
          </Link>
        </div>
      )}

      {/* KPI Metric Cards */}
      <div className="metrics-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px', marginBottom: '20px' }}>
        <MetricCard
          title="Active Incidents"
          value={incidentStats?.open_incidents !== undefined ? incidentStats.open_incidents : incidents.filter(i => i.status === 'OPEN').length}
          subtext={`${incidentStats?.critical_incidents || 0} critical priority`}
          icon={AlertOctagon}
          badge={incidentStats?.critical_incidents > 0 ? 'CRITICAL' : 'STABLE'}
          badgeClass={incidentStats?.critical_incidents > 0 ? 'badge-critical' : 'badge-success'}
          onClick={() => navigate('/incidents')}
        />
        <MetricCard
          title="Highest Threat Risk"
          value={formatScore(highestRiskScore)}
          subtext={`Current level: ${highestRiskLevel}`}
          icon={ShieldCheck}
          badge={highestRiskLevel}
          badgeClass={getRiskBadgeClass(highestRiskLevel)}
          onClick={() => navigate('/detection')}
        />
        <MetricCard
          title="Active Firewall Blocks"
          value={blockedIPs.length}
          subtext="Enforced on NETSENTINEL chain"
          icon={Shield}
          badge={blockedIPs.length > 0 ? 'MITIGATING' : 'IDLE'}
          badgeClass={blockedIPs.length > 0 ? 'badge-warning' : 'badge-info'}
          onClick={() => navigate('/firewall')}
        />
        <MetricCard
          title="Packet Ingestion Rate"
          value={formatNumber(trafficMetrics?.current_pps || 0, 0)}
          subtext={formatRate(trafficMetrics?.current_bps || 0, 'bps')}
          icon={Radio}
          badge={trafficMetrics?.status?.toUpperCase() || 'STOPPED'}
          badgeClass={trafficMetrics?.status === 'running' ? 'badge-success' : 'badge-warning'}
          onClick={() => navigate('/network')}
        />
        <MetricCard
          title="Host Resources"
          value={formatPercent(telemetry?.cpu_percent || 0)}
          subtext={`RAM: ${formatPercent(telemetry?.memory_percent || 0)} (${formatBytes(telemetry?.memory_used_bytes)} used)`}
          icon={Cpu}
          onClick={() => navigate('/host')}
        />
      </div>

      {/* Two-Column Overview Layout */}
      <div className="dashboard-grid">
        {/* Network Traffic Trend */}
        <DashboardCard title="Real-Time Network Activity" icon={Activity}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Current: <strong style={{ color: 'var(--accent-cyan)' }}>{formatNumber(trafficMetrics?.current_pps || 0)} pps</strong> / <strong style={{ color: 'var(--accent-blue)' }}>{formatRate(trafficMetrics?.current_bps || 0, 'bps')}</strong>
            </div>
            <Link to="/network" style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '4px', textDecoration: 'none' }}>
              Full Network View <ArrowRight size={14} />
            </Link>
          </div>

          {trafficHistory.length > 0 ? (
            <div style={{ height: '180px', width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficHistory}>
                  <defs>
                    <linearGradient id="ppsGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} width={35} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#131b2e', borderColor: '#1e293b', fontSize: '11px' }}
                    labelStyle={{ color: '#94a3b8' }}
                  />
                  <Area type="monotone" dataKey="pps" stroke="#06b6d4" fillOpacity={1} fill="url(#ppsGrad)" name="Packets/sec" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <LoadingState message="Awaiting live traffic metrics..." compact />
          )}
        </DashboardCard>

        {/* Recent Incidents Preview */}
        <DashboardCard title="Active Incident Queue" icon={AlertOctagon}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Recent active correlated threats
            </span>
            <Link to="/incidents" style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '4px', textDecoration: 'none' }}>
              All Incidents ({incidents.length}) <ArrowRight size={14} />
            </Link>
          </div>

          {incidents.length > 0 ? (
            <div className="incident-table-wrapper" style={{ maxHeight: '230px', overflowY: 'auto' }}>
              <table className="incident-table" style={{ fontSize: '0.8rem' }}>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Incident</th>
                    <th>Attacker IP</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.slice(0, 5).map((inc) => (
                    <tr
                      key={inc.incident_id}
                      onClick={() => navigate(`/incidents/${encodeURIComponent(inc.incident_id)}`)}
                      style={{ cursor: 'pointer' }}
                      title="Click to view incident investigation details"
                    >
                      <td>
                        <SeverityBadge severity={inc.severity} />
                      </td>
                      <td>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                          {inc.incident_id}
                        </div>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                          {inc.title}
                        </div>
                      </td>
                      <td>
                        <code style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
                          {inc.primary_source_ip || '—'}
                        </code>
                      </td>
                      <td>
                        <span className={`badge ${getIncidentStatusBadgeClass(inc.status)}`}>
                          {inc.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              title="No Open Incidents"
              message="No security incidents currently active."
              icon={ShieldCheck}
            />
          )}
        </DashboardCard>

        {/* Recent Risk Assessments Preview */}
        <DashboardCard title="Recent Threat Assessments" icon={ShieldCheck}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Composite Rule + ML Risk Evaluations
            </span>
            <Link to="/detection" style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '4px', textDecoration: 'none' }}>
              Detection Engine <ArrowRight size={14} />
            </Link>
          </div>

          {recentRisks.length > 0 ? (
            <div className="alerts-list" style={{ maxHeight: '200px', overflowY: 'auto' }}>
              {recentRisks.map((r, idx) => (
                <div key={idx} className="alert-item" style={{ padding: '8px 10px', marginBottom: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className={`badge ${getRiskBadgeClass(r.risk_level)}`} style={{ fontSize: '10px' }}>
                        {r.risk_level}
                      </span>
                      <code style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>
                        {r.source_ip || '—'}
                      </code>
                    </div>
                    <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                      Risk: {formatScore(r.risk_score)}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                    Rule: {r.rule_type || 'NONE'} | Actions: {Array.isArray(r.actions) ? r.actions.join(', ') : 'LOG'}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              title="No Risk Alerts"
              message="No recent anomalous risk assessments evaluated."
              icon={ShieldCheck}
            />
          )}
        </DashboardCard>

        {/* Active Firewall Mitigations Preview */}
        <DashboardCard title="Firewall Mitigation Status" icon={Shield}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Active Blocks: <strong style={{ color: 'var(--text-primary)' }}>{blockedIPs.length}</strong>
            </span>
            <Link to="/firewall" style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '4px', textDecoration: 'none' }}>
              Firewall Console <ArrowRight size={14} />
            </Link>
          </div>

          {blockedIPs.length > 0 ? (
            <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
              {blockedIPs.slice(0, 5).map((b, idx) => (
                <div key={idx} style={{ padding: '8px 10px', background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.25)', borderRadius: '4px', marginBottom: '6px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <code style={{ color: '#fca5a5', fontWeight: 600 }}>{b.ip}</code>
                    <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>{b.reason || 'Auto-mitigated'}</div>
                  </div>
                  <span className="badge badge-danger" style={{ fontSize: '10px' }}>BLOCKED</span>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              title="Zero Active Blocks"
              message="No hosts are currently blocked by firewall mitigation rules."
              icon={ShieldCheck}
            />
          )}
        </DashboardCard>
      </div>
    </div>
  );
}

export default Overview;
