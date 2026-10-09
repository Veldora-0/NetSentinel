import React, { useState, useEffect, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  AlertOctagon,
  Shield,
  ShieldCheck,
  Cpu,
  ArrowRight,
  Radio,
  Brain,
  RotateCcw,
  Clock,
  Layers,
  Server,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from 'recharts';
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
  fetchRiskStats,
  fetchMLStatus,
  fetchTelemetryCurrent,
  fetchTelemetryHistory,
} from '../services/api';
import {
  formatNumber,
  formatBytes,
  formatRate,
  formatScore,
  formatPercent,
  safeNumber,
  formatAlertTime,
  getIncidentStatusBadgeClass,
  getRiskBadgeClass,
  SEVERITY_COLORS,
} from '../utils/formatters';

export function Overview() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(new Date());

  // Backend Data State
  const [readiness, setReadiness] = useState(null);
  const [trafficMetrics, setTrafficMetrics] = useState(null);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [summary, setSummary] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [incidentStats, setIncidentStats] = useState(null);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [recentRisks, setRecentRisks] = useState([]);
  const [riskStats, setRiskStats] = useState(null);
  const [mlStatus, setMlStatus] = useState(null);
  const [telemetry, setTelemetry] = useState(null);
  const [telemetryHistory, setTelemetryHistory] = useState([]);

  // Comprehensive Data Fetch
  const loadOverviewData = useCallback(async () => {
    setError(null);
    try {
      const [
        trafficRes,
        sumRes,
        incRes,
        statsRes,
        blockedRes,
        risksRes,
        riskStatsRes,
        mlStatRes,
        telemRes,
        telemHistRes,
      ] = await Promise.allSettled([
        fetchTrafficMetrics(),
        fetchSecuritySummary(),
        fetchIncidents({ limit: 5 }),
        fetchIncidentStats(),
        fetchBlockedIPs(),
        fetchRecentRisks(5),
        fetchRiskStats(),
        fetchMLStatus(),
        fetchTelemetryCurrent(),
        fetchTelemetryHistory(20),
      ]);

      if (trafficRes.status === 'fulfilled' && trafficRes.value) {
        setTrafficMetrics(trafficRes.value);
        // Seed first history point if empty
        setTrafficHistory((prev) => {
          if (prev.length === 0) {
            const nowStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            return [{
              time: nowStr,
              pps: safeNumber(trafficRes.value.current_pps ?? trafficRes.value.packets_per_sec, 0),
              bps: safeNumber(trafficRes.value.current_bps ?? trafficRes.value.bytes_per_sec, 0),
            }];
          }
          return prev;
        });
      }
      if (sumRes.status === 'fulfilled' && sumRes.value?.summary) setSummary(sumRes.value.summary);
      if (incRes.status === 'fulfilled' && incRes.value?.incidents) setIncidents(incRes.value.incidents);
      if (statsRes.status === 'fulfilled' && statsRes.value?.stats) setIncidentStats(statsRes.value.stats);
      if (blockedRes.status === 'fulfilled' && Array.isArray(blockedRes.value)) setBlockedIPs(blockedRes.value);
      if (risksRes.status === 'fulfilled' && risksRes.value?.assessments) setRecentRisks(risksRes.value.assessments);
      if (riskStatsRes.status === 'fulfilled' && riskStatsRes.value?.stats) setRiskStats(riskStatsRes.value.stats);
      if (mlStatRes.status === 'fulfilled' && mlStatRes.value) setMlStatus(mlStatRes.value);
      if (telemRes.status === 'fulfilled' && telemRes.value?.telemetry) setTelemetry(telemRes.value.telemetry);
      if (telemHistRes.status === 'fulfilled' && telemHistRes.value?.history) {
        const formatted = telemHistRes.value.history.map((h) => ({
          time: formatAlertTime(h.timestamp),
          cpu: safeNumber(h.cpu_percent, 0),
          memory: safeNumber(h.memory_percent, 0),
        }));
        setTelemetryHistory(formatted);
      }
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.message || 'Failed to refresh operations overview');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadOverviewData();
    const interval = setInterval(loadOverviewData, 20000);
    return () => clearInterval(interval);
  }, [loadOverviewData]);

  // Real-Time Socket Stream Handlers
  useSocketEvent('traffic_metrics', (data) => {
    if (!data) return;
    setTrafficMetrics(data);
    const nowStr = new Date(Number(data.timestamp || Date.now() / 1000) * 1000).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
    setTrafficHistory((prev) => {
      const pps = safeNumber(data.current_pps ?? data.packets_per_sec, 0);
      const bps = safeNumber(data.current_bps ?? data.bytes_per_sec, 0);
      const updated = [...prev, { time: nowStr, pps, bps }];
      return updated.length > 25 ? updated.slice(-25) : updated;
    });
  });

  useSocketEvent('host_telemetry', (data) => {
    if (!data) return;
    setTelemetry(data);
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
      return updated.length > 25 ? updated.slice(-25) : updated;
    });
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

  useSocketEvent('firewall_action', () => {
    fetchBlockedIPs().then((ips) => {
      if (Array.isArray(ips)) setBlockedIPs(ips);
    });
  });

  useSocketEvent('risk_assessment', (data) => {
    if (!data) return;
    setRecentRisks((prev) => [data, ...prev.slice(0, 4)]);
  });

  useSocketEvent('ml_status', (data) => {
    if (data) setMlStatus(data);
  });

  // Calculate highest current risk score
  const highestRiskScore = recentRisks.length > 0
    ? Math.max(...recentRisks.map((r) => safeNumber(r.risk_score ?? r.combined_score, 0)))
    : safeNumber(riskStats?.highest_risk_score, 0);

  const highestRiskLevel = recentRisks.length > 0
    ? recentRisks[0]?.risk_level || 'LOW'
    : 'LOW';

  const isReady = readiness?.ready === true;
  const isMlReady = mlStatus?.model_status === 'READY' || mlStatus?.model_ready === true;
  const isMlCollecting = mlStatus?.model_status === 'COLLECTING' || mlStatus?.is_collecting === true;

  // Severity Distribution Data from Summary or Risk Stats
  const severityBreakdown = [
    {
      name: 'LOW',
      count: safeNumber(summary?.severities?.LOW ?? riskStats?.low_count, 0),
      color: SEVERITY_COLORS.LOW,
    },
    {
      name: 'MEDIUM',
      count: safeNumber(summary?.severities?.MEDIUM ?? riskStats?.medium_count, 0),
      color: SEVERITY_COLORS.MEDIUM,
    },
    {
      name: 'HIGH',
      count: safeNumber(summary?.severities?.HIGH ?? riskStats?.high_count, 0),
      color: SEVERITY_COLORS.HIGH,
    },
    {
      name: 'CRITICAL',
      count: safeNumber(summary?.severities?.CRITICAL ?? riskStats?.critical_count, 0),
      color: SEVERITY_COLORS.CRITICAL,
    },
  ];

  const totalSeverityCount = severityBreakdown.reduce((sum, item) => sum + item.count, 0);

  return (
    <div className="page-container">
      <PageHeader
        title="Security Operations Overview"
        subtitle="Real-time situational awareness across packet capture, hybrid detection rules, ML anomalies, and correlated incidents"
        actions={
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
              Updated: {lastUpdated.toLocaleTimeString()}
            </span>
            <button className="btn-refresh" onClick={loadOverviewData} title="Refresh Operations Posture">
              <RotateCcw size={14} /> Refresh
            </button>
            <Link to="/incidents" className="btn btn-primary" style={{ padding: '0.4rem 0.85rem', fontSize: '0.8rem', textDecoration: 'none' }}>
              Investigate Incidents
            </Link>
          </div>
        }
      />

      {error && <ErrorState message={error} onRetry={loadOverviewData} />}

      {/* Readiness / Degradation Alert Banner */}
      {readiness && !readiness.ready && (
        <div className="safety-banner warning">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertTriangle size={18} style={{ color: '#f59e0b', flexShrink: 0 }} />
            <span>
              <strong>Operational Notice:</strong> Subsystem readiness is currently degraded. One or more workers are initializing or offline.
            </span>
          </div>
          <Link to="/system" className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: '0.75rem', textDecoration: 'none' }}>
            Inspect System Health
          </Link>
        </div>
      )}

      {/* Top-Level KPI Metric Cards */}
      <div className="metric-cards-grid">
        <MetricCard
          title="System Health"
          value={isReady ? 'OPERATIONAL' : readiness ? 'DEGRADED' : 'CHECKING'}
          subtext={`API: Online | Socket: Live`}
          icon={Server}
          badge={<StatusBadge status={isReady ? 'HEALTHY' : 'WARNING'} text={isReady ? 'HEALTHY' : 'DEGRADED'} />}
          onClick={() => navigate('/system')}
        />
        <MetricCard
          title="Network Traffic"
          value={`${formatNumber(trafficMetrics?.current_pps ?? trafficMetrics?.packets_per_sec ?? 0, 0)} pps`}
          subtext={formatRate(trafficMetrics?.current_bps ?? trafficMetrics?.bytes_per_sec ?? 0, 'bps')}
          icon={Radio}
          badge={<span className={`badge ${trafficMetrics?.status === 'running' ? 'badge-success' : 'badge-neutral'}`}>{trafficMetrics?.status?.toUpperCase() || 'STANDBY'}</span>}
          onClick={() => navigate('/network')}
        />
        <MetricCard
          title="Active Incidents"
          value={formatNumber(incidentStats?.open_incidents ?? incidents.filter((i) => i.status === 'OPEN').length, 0)}
          subtext={`${incidentStats?.critical_incidents || 0} critical priority`}
          icon={AlertOctagon}
          badge={
            (incidentStats?.critical_incidents || 0) > 0 ? (
              <span className="badge badge-critical">CRITICAL</span>
            ) : (
              <span className="badge badge-success">STABLE</span>
            )
          }
          onClick={() => navigate('/incidents')}
        />
        <MetricCard
          title="Highest Threat Risk"
          value={formatScore(highestRiskScore)}
          subtext={`Current level: ${highestRiskLevel}`}
          icon={ShieldCheck}
          badge={<span className={`badge ${getRiskBadgeClass(highestRiskLevel)}`}>{highestRiskLevel}</span>}
          onClick={() => navigate('/detection')}
        />
        <MetricCard
          title="ML Anomaly Engine"
          value={isMlReady ? 'MODEL READY' : isMlCollecting ? 'COLLECTING' : 'INITIALIZING'}
          subtext={`Baseline: ${mlStatus?.baseline_samples_collected ?? 0}/${mlStatus?.baseline_target_samples ?? 10} samples`}
          icon={Brain}
          badge={<StatusBadge status={isMlReady ? 'HEALTHY' : 'INITIALIZING'} text={isMlReady ? 'ONLINE' : 'TRAINING'} />}
          onClick={() => navigate('/detection')}
        />
      </div>

      {/* Main Visualization Grid */}
      <div className="dashboard-grid">
        {/* Network Traffic Trend */}
        <DashboardCard
          title="Network Traffic Rate (Packets / Second)"
          icon={Activity}
          headerRight={
            <Link to="/network" style={{ fontSize: '0.76rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '4px', textDecoration: 'none' }}>
              Network Workspace <ArrowRight size={13} />
            </Link>
          }
        >
          {trafficHistory.length > 0 ? (
            <div style={{ height: '200px', width: '100%', marginTop: '6px' }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficHistory} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="overviewPpsGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} width={40} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                    labelStyle={{ color: '#94a3b8' }}
                  />
                  <Area
                    type="monotone"
                    dataKey="pps"
                    stroke="#06b6d4"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#overviewPpsGrad)"
                    name="Packets/sec"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <LoadingState message="Awaiting live traffic telemetry..." compact />
          )}
        </DashboardCard>

        {/* Threat Severity Distribution */}
        <DashboardCard
          title="Security Event Severity Distribution"
          icon={ShieldCheck}
          headerRight={
            <Link to="/detection" style={{ fontSize: '0.76rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '4px', textDecoration: 'none' }}>
              Detection Engine <ArrowRight size={13} />
            </Link>
          }
        >
          {totalSeverityCount > 0 ? (
            <div style={{ height: '200px', width: '100%', marginTop: '6px' }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityBreakdown} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} width={35} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                    formatter={(val) => [`${val} events`, 'Count']}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {severityBreakdown.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState
              title="No Security Events Recorded"
              message="No security alerts or threat classifications have occurred yet."
              icon={ShieldCheck}
            />
          )}
        </DashboardCard>

        {/* Host Resource Trend */}
        <DashboardCard
          title="Host Resources & Utilization History"
          icon={Cpu}
          headerRight={
            <Link to="/host" style={{ fontSize: '0.76rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '4px', textDecoration: 'none' }}>
              Host Security <ArrowRight size={13} />
            </Link>
          }
        >
          {telemetryHistory.length > 0 ? (
            <div style={{ height: '200px', width: '100%', marginTop: '6px' }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={telemetryHistory} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} width={40} domain={[0, 100]} tickFormatter={(v) => `${v}%`} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                    formatter={(val, name) => [`${val}%`, name]}
                  />
                  <Line type="monotone" dataKey="cpu" stroke="#38bdf8" strokeWidth={2} dot={false} name="CPU %" />
                  <Line type="monotone" dataKey="memory" stroke="#10b981" strokeWidth={2} dot={false} name="Memory %" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          ) : telemetry ? (
            <div style={{ padding: '1rem', display: 'flex', justifyContent: 'space-around', alignItems: 'center' }}>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>CPU Utilization</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#38bdf8' }}>{formatPercent(telemetry.cpu_percent)}</div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Memory Utilization</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#10b981' }}>{formatPercent(telemetry.memory_percent)}</div>
              </div>
            </div>
          ) : (
            <LoadingState message="Collecting host telemetry samples..." compact />
          )}
        </DashboardCard>

        {/* Active Incident Queue - Full Width across columns */}
        <DashboardCard
          title="Active Correlated Incidents"
          icon={AlertOctagon}
          style={{ gridColumn: '1 / -1' }}
          headerRight={
            <Link to="/incidents" style={{ fontSize: '0.76rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '4px', textDecoration: 'none' }}>
              All Incidents ({incidents.length}) <ArrowRight size={13} />
            </Link>
          }
        >
          {incidents.length > 0 ? (
            <div style={{ overflowX: 'auto', maxHeight: '200px' }}>
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Incident</th>
                    <th>Source IP</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.slice(0, 5).map((inc) => (
                    <tr
                      key={inc.incident_id}
                      onClick={() => navigate(`/incidents/${encodeURIComponent(inc.incident_id)}`)}
                      style={{ cursor: 'pointer' }}
                      title="View incident investigation details"
                    >
                      <td>
                        <SeverityBadge severity={inc.severity} />
                      </td>
                      <td>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                          {inc.incident_id}
                        </div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                          {inc.title}
                        </div>
                      </td>
                      <td>
                        <code style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
                          {inc.primary_source_ip || inc.correlation_key || '—'}
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
              message="No correlated security incidents currently active."
              icon={ShieldCheck}
            />
          )}
        </DashboardCard>
      </div>

      {/* Recent Activity & Mitigation Posture Grid */}
      <div className="dashboard-grid" style={{ marginTop: '0.5rem' }}>
        {/* Recent Risk Assessments Feed */}
        <DashboardCard
          title="Recent Evaluated Threat Assessments"
          icon={ShieldCheck}
          headerRight={
            <Link to="/detection" style={{ fontSize: '0.76rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '4px', textDecoration: 'none' }}>
              Risk Engine <ArrowRight size={13} />
            </Link>
          }
        >
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
                        {r.source_ip || 'Host Activity'}
                      </code>
                    </div>
                    <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                      Score: {formatScore(r.risk_score ?? r.combined_score)}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.73rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                    Category: {r.category || r.rule_type || 'DETECTION'} | Action: {Array.isArray(r.actions) ? r.actions.join(', ') : r.action || 'LOG'}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              title="No Risk Alerts"
              message="No anomalous risk scores recently evaluated."
              icon={ShieldCheck}
            />
          )}
        </DashboardCard>

        {/* Active Firewall & Defense Posture */}
        <DashboardCard
          title="Firewall Defense Posture"
          icon={Shield}
          headerRight={
            <Link to="/firewall" style={{ fontSize: '0.76rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '4px', textDecoration: 'none' }}>
              Firewall Console <ArrowRight size={13} />
            </Link>
          }
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div style={{ padding: '10px 12px', background: 'rgba(56, 189, 248, 0.05)', border: '1px solid rgba(56, 189, 248, 0.15)', borderRadius: '6px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Kernel iptables Integration</span>
                <span className="badge badge-info" style={{ fontSize: '10px' }}>EVALUATION MODE</span>
              </div>
              <div>Firewall enforcement is in evaluation/standby mode (`NETSENTINEL_FIREWALL_ENABLED=false`). Drops are observed without mutating live kernel chains.</div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', background: 'var(--bg-dark)', borderRadius: '6px', fontSize: '0.82rem' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Active Mitigated Hosts:</span>
              <span style={{ fontWeight: 700, color: blockedIPs.length > 0 ? '#ef4444' : 'var(--text-primary)' }}>
                {blockedIPs.length} IPs
              </span>
            </div>
          </div>
        </DashboardCard>
      </div>
    </div>
  );
}

export default Overview;
