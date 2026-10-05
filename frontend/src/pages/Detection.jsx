import React, { useState, useEffect } from 'react';
import {
  Brain,
  ShieldCheck,
  BarChart2,
  RefreshCw,
  AlertTriangle,
  Zap,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ReferenceLine,
} from 'recharts';
import { PageHeader } from '../components/layout/PageHeader';
import { DashboardCard } from '../components/DashboardCard';
import { MetricCard } from '../components/common/MetricCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
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
  getRiskBadgeClass,
} from '../utils/formatters';

export function Detection() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [mlStatus, setMlStatus] = useState(null);
  const [mlMetrics, setMlMetrics] = useState({ window_history: [], recent_anomalies: [] });
  const [riskStats, setRiskStats] = useState(null);
  const [recentRisks, setRecentRisks] = useState([]);
  const [summary, setSummary] = useState(null);

  const loadDetectionData = async () => {
    setLoading(true);
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
      if (risksRes.status === 'fulfilled' && risksRes.value?.assessments) setRecentRisks(risksRes.value.assessments);
      if (riskStatRes.status === 'fulfilled' && riskStatRes.value?.stats) setRiskStats(riskStatRes.value.stats);
      if (sumRes.status === 'fulfilled' && sumRes.value?.summary) setSummary(sumRes.value.summary);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDetectionData();
  }, []);

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
  }));

  const isModelReady = mlStatus?.model_ready === true;
  const isCollecting = mlStatus?.is_collecting === true;

  return (
    <div className="detection-page">
      <PageHeader
        title="Intrusion Detection & Composite Risk Engine"
        subtitle="Dual-engine pipeline combining signature rules and unsupervised Isolation Forest anomaly scoring"
        actions={
          <button className="btn btn-secondary" onClick={loadDetectionData} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            Refresh
          </button>
        }
      />

      {error && <ErrorState error={error} onRetry={loadDetectionData} />}

      {/* KPI Cards */}
      <div className="metrics-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px', marginBottom: '20px' }}>
        <MetricCard
          title="Isolation Forest Status"
          value={isModelReady ? 'TRAINED' : isCollecting ? 'COLLECTING' : 'INITIALIZING'}
          subtext={`Baseline: ${mlStatus?.windows_collected || 0} / ${mlStatus?.baseline_windows_target || 10} windows`}
          icon={Brain}
          badge={isModelReady ? 'READY' : 'TRAINING'}
          badgeClass={isModelReady ? 'badge-success' : 'badge-warning'}
        />
        <MetricCard
          title="Total Risk Assessments"
          value={formatNumber(riskStats?.total_assessments || summary?.risks_total || recentRisks.length)}
          subtext={`High: ${riskStats?.high_risk_count || 0} | Critical: ${riskStats?.critical_risk_count || 0}`}
          icon={ShieldCheck}
        />
        <MetricCard
          title="Total Security Detections"
          value={formatNumber(summary?.events_total || 0)}
          subtext={`Last 24h: ${formatNumber(summary?.events_last_24h || 0)} events`}
          icon={BarChart2}
        />
        <MetricCard
          title="Automated Mitigations"
          value={formatNumber(summary?.mitigations_total || 0)}
          subtext={`Auto-block Threshold: >= 0.80 score`}
          icon={Zap}
        />
      </div>

      {/* Machine Learning Model Details & Anomaly Chart */}
      <div className="dashboard-grid">
        <DashboardCard title="Machine Learning Anomaly Detection (Isolation Forest)" icon={Brain}>
          <div className="status-detail-list">
            <div className="detail-item">
              <span className="detail-label">Model Lifecycle:</span>
              <span className={`badge ${isModelReady ? 'badge-success' : 'badge-warning'}`}>
                {isModelReady ? 'MODEL READY' : isCollecting ? 'COLLECTING BASELINE' : 'AWAITING TRAFFIC'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Aggregation Window:</span>
              <span className="detail-value">{mlStatus?.window_seconds || 5.0} seconds</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Contamination Hyperparameter:</span>
              <span className="detail-value">{mlStatus?.contamination || 'auto'}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Number of Estimators:</span>
              <span className="detail-value">{mlStatus?.n_estimators || 100} Isolation Trees</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Total Anomalies Detected:</span>
              <span className={`badge ${(mlStatus?.total_anomalies || 0) > 0 ? 'badge-warning' : 'badge-success'}`}>
                {mlStatus?.total_anomalies || 0}
              </span>
            </div>
          </div>
        </DashboardCard>

        {/* Anomaly Trend Chart */}
        <DashboardCard title="Window Anomaly Score History" icon={BarChart2}>
          {chartData.length > 0 ? (
            <div style={{ height: '220px', width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} domain={[0, 1]} width={35} />
                  <Tooltip contentStyle={{ backgroundColor: '#131b2e', borderColor: '#1e293b' }} />
                  <ReferenceLine y={0.5} stroke="#ef4444" strokeDasharray="3 3" label={{ value: 'Anomaly Threshold (0.5)', fill: '#ef4444', fontSize: 10 }} />
                  <Area type="monotone" dataKey="score" stroke="#f59e0b" fillOpacity={1} fill="url(#scoreGrad)" name="Anomaly Score" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <LoadingState message="Collecting window traffic features..." />
          )}
        </DashboardCard>
      </div>

      {/* Composite Risk Engine Configuration & Recent Assessments */}
      <div style={{ marginTop: '20px' }}>
        <DashboardCard title="Composite Risk Scoring Formula & Evidence Breakdown" icon={ShieldCheck}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginBottom: '16px', background: 'var(--bg-dark)', padding: '14px', borderRadius: '6px' }}>
            <div>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
                Formula Breakdown
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                <code>Risk = (0.65 × Rule_Score) + (0.35 × ML_Score) + Freq_Boost + Cross_Domain_Boost + TI_Modifier</code>
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
                Operational Thresholds
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                Low: &lt; 0.40 | Medium: 0.40–0.69 | High: 0.70–0.79 | Critical: &ge; 0.80 (Auto-Block)
              </div>
            </div>
          </div>

          {recentRisks.length > 0 ? (
            <div className="incident-table-wrapper" style={{ maxHeight: '340px', overflowY: 'auto' }}>
              <table className="incident-table" style={{ fontSize: '0.8rem' }}>
                <thead>
                  <tr>
                    <th>Level</th>
                    <th>Score</th>
                    <th>Source IP</th>
                    <th>Rule Component</th>
                    <th>ML Component</th>
                    <th>Actions Taken</th>
                    <th>Evaluated At</th>
                  </tr>
                </thead>
                <tbody>
                  {recentRisks.map((r, idx) => (
                    <tr key={idx}>
                      <td>
                        <span className={`badge ${getRiskBadgeClass(r.risk_level)}`}>
                          {r.risk_level}
                        </span>
                      </td>
                      <td>
                        <strong style={{ color: 'var(--text-primary)' }}>
                          {formatScore(r.risk_score)}
                        </strong>
                      </td>
                      <td>
                        <code style={{ color: 'var(--accent-cyan)' }}>{r.source_ip || '—'}</code>
                      </td>
                      <td>
                        {r.rule_type || 'NONE'} ({formatScore(r.rule_score || 0)})
                      </td>
                      <td>
                        {formatScore(r.ml_score || 0)}
                      </td>
                      <td>
                        {Array.isArray(r.actions) ? (
                          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                            {r.actions.map((act, aIdx) => (
                              <span key={aIdx} className={`badge ${act === 'BLOCK' ? 'badge-danger' : 'badge-secondary'}`} style={{ fontSize: '10px' }}>
                                {act}
                              </span>
                            ))}
                          </div>
                        ) : (
                          'LOG'
                        )}
                      </td>
                      <td>{formatAlertTime(r.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              title="No Risk Assessments"
              message="No composite risk evaluations recorded yet."
              icon={ShieldCheck}
            />
          )}
        </DashboardCard>
      </div>
    </div>
  );
}

export default Detection;
