import React, { useState, useEffect, useCallback } from 'react';
import {
  Brain,
  ShieldCheck,
  BarChart2,
  RotateCcw,
  AlertTriangle,
  Zap,
  Layers,
  Activity,
  ShieldAlert,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
  ReferenceLine,
} from 'recharts';
import { PageHeader } from '../components/layout/PageHeader';
import { DashboardCard } from '../components/DashboardCard';
import { MetricCard } from '../components/common/MetricCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { useSocketEvent } from '../hooks/useSocketEvent';
import {
  fetchMLStatus,
  fetchMLMetrics,
  fetchRecentRisks,
  fetchRiskStats,
  fetchSecuritySummary,
} from '../services/api';
import {
  formatNumber,
  formatPercent,
  formatScore,
  formatAlertTime,
  formatDetectionType,
  safeNumber,
  getRiskBadgeClass,
  SEVERITY_COLORS,
} from '../utils/formatters';

export function Detection() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [mlStatus, setMlStatus] = useState(null);
  const [mlMetrics, setMlMetrics] = useState({ window_history: [], recent_anomalies: [] });
  const [riskStats, setRiskStats] = useState(null);
  const [recentRisks, setRecentRisks] = useState([]);
  const [summary, setSummary] = useState(null);

  const loadDetectionData = useCallback(async () => {
    setError(null);
    try {
      const [mlStatRes, mlMetRes, risksRes, riskStatRes, sumRes] = await Promise.allSettled([
        fetchMLStatus(),
        fetchMLMetrics(),
        fetchRecentRisks(50),
        fetchRiskStats(),
        fetchSecuritySummary(),
      ]);

      if (mlStatRes.status === 'fulfilled' && mlStatRes.value) setMlStatus(mlStatRes.value);
      if (mlMetRes.status === 'fulfilled' && mlMetRes.value) setMlMetrics(mlMetRes.value);
      if (risksRes.status === 'fulfilled' && risksRes.value) {
        setRecentRisks(Array.isArray(risksRes.value) ? risksRes.value : (risksRes.value.assessments || []));
      }
      if (riskStatRes.status === 'fulfilled' && riskStatRes.value) {
        setRiskStats(riskStatRes.value.stats || riskStatRes.value);
      }
      if (sumRes.status === 'fulfilled' && sumRes.value) {
        setSummary(sumRes.value.summary || sumRes.value);
      }
    } catch (err) {
      setError(err.message || 'Failed to load detection and risk data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDetectionData();
    const interval = setInterval(loadDetectionData, 12000);
    return () => clearInterval(interval);
  }, [loadDetectionData]);

  // Socket.IO event listeners
  useSocketEvent('ml_status', (data) => {
    if (data) setMlStatus(data);
  });

  useSocketEvent('ml_anomaly', (data) => {
    if (!data) return;
    setMlMetrics((prev) => ({
      ...prev,
      recent_anomalies: [data, ...(prev.recent_anomalies || []).slice(0, 29)],
    }));
  });

  useSocketEvent('risk_assessment', (data) => {
    if (!data) return;
    setRecentRisks((prev) => [data, ...prev.slice(0, 49)]);
  });

  useSocketEvent('risk_status', (data) => {
    if (data) setRiskStats(data);
  });

  useSocketEvent('security_summary', (data) => {
    if (data) setSummary(data);
  });

  // Safe ML chart series formatting
  const chartData = (mlMetrics?.window_history || []).map((w, idx) => ({
    index: idx + 1,
    time: formatAlertTime(w.timestamp),
    score: Number(w.anomaly_score !== undefined ? w.anomaly_score : 0),
    is_anomaly: Boolean(w.is_anomaly),
    prediction: w.prediction || (w.is_anomaly ? 'ANOMALY' : 'NORMAL'),
  }));

  const modelStatusStr = (mlStatus?.model_status || '').toUpperCase();
  const isModelReady = modelStatusStr === 'READY' || mlStatus?.model_ready === true;
  const isCollecting = modelStatusStr === 'COLLECTING' || mlStatus?.is_collecting === true;

  // Real Detection-Type Distribution from Backend
  const detectionTypeData = Object.entries(summary?.detection_types || {})
    .map(([type, count]) => ({
      rawType: type,
      name: formatDetectionType(type),
      count: Number(count),
    }))
    .sort((a, b) => b.count - a.count);

  const totalDetectionsCount = detectionTypeData.reduce((acc, d) => acc + d.count, 0);

  // Severity Distribution from Summary or Risk Stats
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

  return (
    <div className="page-container">
      <PageHeader
        title="Intrusion Detection & Composite Risk Engine"
        subtitle="Dual-engine pipeline combining signature rule inspection and unsupervised Isolation Forest anomaly scoring"
        actions={
          <button className="btn-refresh" onClick={loadDetectionData} title="Refresh Detection Telemetry">
            <RotateCcw size={14} /> Refresh
          </button>
        }
      />

      {error && <ErrorState message={error} onRetry={loadDetectionData} />}

      {/* KPI Cards */}
      <div className="metric-cards-grid">
        <MetricCard
          title="Isolation Forest Model"
          value={isModelReady ? 'MODEL READY' : isCollecting ? 'COLLECTING' : 'INITIALIZING'}
          subtext={
            isModelReady
              ? `Baseline: ${mlStatus?.training_sample_count || mlStatus?.baseline_samples_collected || 10} / ${mlStatus?.baseline_target_samples || 10} samples (Active)`
              : `Baseline: ${mlStatus?.baseline_samples_collected ?? 0} / ${mlStatus?.baseline_target_samples ?? 10} samples`
          }
          icon={Brain}
          badge={
            <StatusBadge
              status={isModelReady ? 'HEALTHY' : 'INITIALIZING'}
              text={isModelReady ? 'ONLINE' : isCollecting ? 'COLLECTING' : 'TRAINING'}
            />
          }
        />
        <MetricCard
          title="Total Risk Assessments"
          value={formatNumber(riskStats?.total_assessments ?? summary?.total_assessments ?? recentRisks.length)}
          subtext={`Avg Score: ${formatScore(riskStats?.average_risk_score, 3)} | High: ${formatScore(riskStats?.highest_risk_score, 3)}`}
          icon={ShieldCheck}
        />
        <MetricCard
          title="Elevated Risk Events"
          value={formatNumber((riskStats?.high_count || 0) + (riskStats?.critical_count || 0))}
          subtext={`High: ${riskStats?.high_count || 0} | Critical: ${riskStats?.critical_count || 0}`}
          icon={ShieldAlert}
          badge={
            (riskStats?.critical_count || 0) > 0 ? (
              <span className="badge badge-critical">{riskStats.critical_count} CRITICAL</span>
            ) : (
              <span className="badge badge-neutral">STABLE</span>
            )
          }
        />
        <MetricCard
          title="Security Event Detections"
          value={formatNumber(summary?.total_events ?? summary?.events_total ?? totalDetectionsCount)}
          subtext={`Automated Mitigations: ${formatNumber(summary?.total_firewall_actions ?? 0)}`}
          icon={Zap}
        />
      </div>

      {/* Machine Learning Model Lifecycle & Anomaly Trend */}
      <div className="dashboard-grid">
        <DashboardCard title="Machine Learning Anomaly Detection (Isolation Forest)" icon={Brain}>
          <div className="status-detail-list">
            <div className="detail-item">
              <span className="detail-label">Model Lifecycle Status:</span>
              <span className={`badge ${isModelReady ? 'badge-success' : 'badge-warning'}`}>
                {isModelReady ? 'MODEL READY' : isCollecting ? 'COLLECTING BASELINE' : 'AWAITING TRAFFIC'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Aggregation Window:</span>
              <span className="detail-value">{mlStatus?.window_seconds || 5.0} seconds</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Algorithm:</span>
              <span className="detail-value">Unsupervised Isolation Forest ({mlStatus?.n_estimators || 100} Trees)</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Latest Anomaly Score:</span>
              <span className="detail-value">{formatScore(mlStatus?.latest_anomaly_score, 4)}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Anomalous Windows Detected:</span>
              <span className={`badge ${(mlStatus?.total_anomalies_detected || mlStatus?.total_anomalies || 0) > 0 ? 'badge-warning' : 'badge-success'}`}>
                {mlStatus?.total_anomalies_detected || mlStatus?.total_anomalies || 0}
              </span>
            </div>
          </div>
        </DashboardCard>

        {/* Anomaly Trend Chart */}
        <DashboardCard title="Window Anomaly Score History" icon={BarChart2}>
          {chartData.length > 0 ? (
            <div style={{ height: '220px', width: '100%', marginTop: '6px' }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="anomalyScoreGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} domain={[0, 1]} width={35} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                    labelStyle={{ color: '#94a3b8' }}
                    formatter={(val) => [formatScore(val, 3), 'Anomaly Score']}
                  />
                  <ReferenceLine
                    y={0.5}
                    stroke="#ef4444"
                    strokeDasharray="3 3"
                    label={{ value: 'Anomaly Threshold (0.50)', fill: '#ef4444', fontSize: 10, position: 'insideTopRight' }}
                  />
                  <Area
                    type="monotone"
                    dataKey="score"
                    stroke="#f59e0b"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#anomalyScoreGrad)"
                    name="Anomaly Score"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : isCollecting ? (
            <div className="placeholder-state">
              <Activity size={28} className="placeholder-icon" style={{ color: '#f59e0b' }} />
              <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
                Baseline Traffic Collection in Progress
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Accumulating normal baseline windows ({mlStatus?.baseline_samples_collected ?? 0}/{mlStatus?.baseline_target_samples ?? 10}). Anomaly scoring activates upon baseline completion.
              </div>
            </div>
          ) : (
            <EmptyState
              title="Awaiting Window Telemetry"
              message="No evaluated feature windows recorded yet."
              icon={Brain}
            />
          )}
        </DashboardCard>
      </div>

      {/* Detection-Type Breakdown and Severity Distribution */}
      <div className="dashboard-grid">
        <DashboardCard title="Detection Vector Distribution" icon={Layers}>
          {detectionTypeData.length > 0 ? (
            <div style={{ height: '220px', width: '100%', marginTop: '6px' }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={detectionTypeData.slice(0, 8)}
                  layout="vertical"
                  margin={{ top: 5, right: 20, left: 20, bottom: 0 }}
                >
                  <XAxis type="number" stroke="#64748b" fontSize={10} tickLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} width={100} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                    formatter={(val) => [`${val} occurrences`, 'Frequency']}
                  />
                  <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState
              title="No Detections Recorded"
              message="No intrusion detection signatures or threat vectors have been detected yet."
              icon={ShieldCheck}
            />
          )}
        </DashboardCard>

        <DashboardCard title="Composite Risk Severity Distribution" icon={ShieldAlert}>
          <div style={{ height: '220px', width: '100%', marginTop: '6px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityBreakdown} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} width={35} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                  formatter={(val) => [`${val} assessments`, 'Count']}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityBreakdown.map((entry, index) => (
                    <Cell key={`sev-cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </DashboardCard>
      </div>

      {/* Composite Risk Engine Formula Breakdown */}
      <DashboardCard title="Composite Risk Scoring Formula & Evidence Model" icon={ShieldCheck}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', background: 'var(--bg-dark)', padding: '14px', borderRadius: '6px' }}>
          <div>
            <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
              Formula Specification
            </div>
            <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              <code>Risk = (0.65 × Rule_Score) + (0.35 × ML_Score) + Freq_Boost + Cross_Domain_Boost + TI_Modifier</code>
            </div>
          </div>
          <div>
            <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
              Operational Boundaries
            </div>
            <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
              LOW: &lt; 0.40 | MEDIUM: 0.40–0.69 | HIGH: 0.70–0.79 | CRITICAL: &ge; 0.80 (Auto-Block Threshold)
            </div>
          </div>
        </div>
      </DashboardCard>

      {/* Recent Evaluated Assessments Table */}
      <DashboardCard title={`Recent Evaluated Assessments (${recentRisks.length})`} icon={Activity}>
        {recentRisks.length > 0 ? (
          <div style={{ overflowX: 'auto', maxHeight: '250px' }}>
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source Target</th>
                  <th>Risk Level</th>
                  <th>Composite Score</th>
                  <th>Category</th>
                  <th>Recommended Actions</th>
                </tr>
              </thead>
              <tbody>
                {recentRisks.slice(0, 15).map((r, idx) => (
                  <tr key={idx}>
                    <td>{formatAlertTime(r.timestamp)}</td>
                    <td>
                      <code style={{ color: 'var(--accent-cyan)' }}>{r.source_ip || 'Host-Internal'}</code>
                    </td>
                    <td>
                      <span className={`badge ${getRiskBadgeClass(r.risk_level)}`}>
                        {r.risk_level}
                      </span>
                    </td>
                    <td>
                      <strong>{formatScore(r.risk_score ?? r.combined_score, 3)}</strong>
                    </td>
                    <td>{r.category || r.rule_type || 'SIGNATURE'}</td>
                    <td>
                      <span style={{ fontSize: '0.75rem', color: '#cbd5e1' }}>
                        {Array.isArray(r.actions) ? r.actions.join(', ') : r.action || 'LOG'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No Evaluated Risks"
            message="No anomalous risk scores evaluated in recent traffic."
            icon={ShieldCheck}
          />
        )}
      </DashboardCard>
    </div>
  );
}

export default Detection;
