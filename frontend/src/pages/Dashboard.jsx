import React, { useState } from 'react';
import { 
  Server, 
  AlertTriangle, 
  Activity, 
  ShieldAlert, 
  Cpu, 
  BarChart2, 
  AlertCircle, 
  Clock, 
  ArrowRight, 
  Brain,
  ShieldCheck,
  Lock,
  Unlock,
  Shield,
  HardDrive,
  RotateCcw,
  History,
  Filter,
  Terminal,
  Radio,
  AlertOctagon,
  Layers,
  FileText,
  CheckCircle2,
  X,
  ExternalLink,
  Search
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, ReferenceLine } from 'recharts';
import { DashboardCard } from '../components/DashboardCard';
import {
  fetchIncidentDetail,
  fetchIncidentTimeline,
  fetchIncidentSummary,
} from '../services/api';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatAlertTime(timestamp) {
  if (!timestamp) return '';
  const d = new Date(timestamp * 1000);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatFullTime(timestamp) {
  if (!timestamp) return '';
  const d = new Date(timestamp * 1000);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function getRiskBadgeClass(level) {
  switch ((level || '').toUpperCase()) {
    case 'CRITICAL': return 'badge-critical';
    case 'HIGH': return 'badge-high';
    case 'MEDIUM': return 'badge-medium';
    default: return 'badge-low';
  }
}

function getIncidentStatusBadgeClass(status) {
  switch ((status || '').toUpperCase()) {
    case 'OPEN': return 'badge-status-open';
    case 'ACKNOWLEDGED': return 'badge-status-acknowledged';
    case 'RESOLVED': return 'badge-status-resolved';
    case 'CLOSED': return 'badge-status-closed';
    default: return 'badge-status-open';
  }
}

export function Dashboard({ 
  apiStatus, 
  socketConnected, 
  trafficMetrics, 
  trafficHistory = [], 
  alerts = [],
  mlStatus = null,
  mlMetrics = { window_history: [], recent_anomalies: [] },
  riskAssessments = [],
  riskStats = null,
  firewallStatus = null,
  blockedIPs = [],
  onUnblock = null,
  hostTelemetry = null,
  telemetryHistory = [],
  securitySummary = null,
  historicalEvents = [],
  onRefreshHistory = null,
  hostStatus = null,
  networkStatus = null,
  arpMappings = [],
  incidents = [],
  incidentStats = null,
  onRefreshIncidents = null,
  onAcknowledgeIncident = null,
  onResolveIncident = null,
  onCloseIncident = null,
  onReopenIncident = null,
  fimStatus = null,
  fimEvents = [],
  onRefreshFim = null,
  onFimRebaseline = null,
}) {

  const isCaptureRunning = trafficMetrics?.status === 'running';
  const isPermissionDenied = trafficMetrics?.status === 'permission_denied';

  // Filters for historical table
  const [historyTypeFilter, setHistoryTypeFilter] = useState('ALL');
  const [historySeverityFilter, setHistorySeverityFilter] = useState('ALL');
  const [historySearchIP, setHistorySearchIP] = useState('');

  // Compute live alert breakdown statistics from actual received events
  const stats = alerts.reduce((acc, curr) => {
    const type = curr.detection_type;
    acc[type] = (acc[type] || 0) + 1;
    return acc;
  }, {});

  const latestRisk = riskAssessments.length > 0 ? riskAssessments[0] : null;

  // Filter historical events
  const displayedHistory = historicalEvents.filter((ev) => {
    if (historyTypeFilter !== 'ALL' && ev.detection_type !== historyTypeFilter) return false;
    if (historySeverityFilter !== 'ALL' && ev.severity !== historySeverityFilter) return false;
    if (historySearchIP.trim() && !(ev.source_ip || 'local').toLowerCase().includes(historySearchIP.trim().toLowerCase())) return false;
    return true;
  });

  // Phase 9: Incident Filters and Investigation State
  const [incidentStatusFilter, setIncidentStatusFilter] = useState('ALL');
  const [incidentSeverityFilter, setIncidentSeverityFilter] = useState('ALL');
  const [incidentSearchQuery, setIncidentSearchQuery] = useState('');

  // Investigation Modal / Drawer State
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [incidentDetail, setIncidentDetail] = useState(null);
  const [incidentTimeline, setIncidentTimeline] = useState([]);
  const [incidentSummaryReport, setIncidentSummaryReport] = useState(null);
  const [modalTab, setModalTab] = useState('timeline');
  const [analystNoteInput, setAnalystNoteInput] = useState('');
  const [resolutionInput, setResolutionInput] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  // Filter incidents for table display
  const displayedIncidents = incidents.filter((inc) => {
    if (incidentStatusFilter !== 'ALL' && inc.status !== incidentStatusFilter) return false;
    if (incidentSeverityFilter !== 'ALL' && inc.severity !== incidentSeverityFilter) return false;
    if (incidentSearchQuery.trim()) {
      const q = incidentSearchQuery.trim().toLowerCase();
      const matchIP = (inc.primary_source_ip || '').toLowerCase().includes(q);
      const matchKey = (inc.correlation_key || '').toLowerCase().includes(q);
      const matchTitle = (inc.title || '').toLowerCase().includes(q);
      const matchId = (inc.incident_id || '').toLowerCase().includes(q);
      if (!matchIP && !matchKey && !matchTitle && !matchId) return false;
    }
    return true;
  });

  const handleOpenInvestigate = async (incId) => {
    setSelectedIncidentId(incId);
    setIncidentDetail(null);
    setIncidentTimeline([]);
    setIncidentSummaryReport(null);
    setAnalystNoteInput('');
    setResolutionInput('');
    setModalTab('timeline');

    try {
      const [detail, timeline, summary] = await Promise.all([
        fetchIncidentDetail(incId),
        fetchIncidentTimeline(incId),
        fetchIncidentSummary(incId),
      ]);
      if (detail) setIncidentDetail(detail);
      if (timeline) setIncidentTimeline(timeline);
      if (summary) setIncidentSummaryReport(summary);
    } catch (err) {
      console.error('Error fetching incident investigation data:', err);
    }
  };

  const handleAction = async (type) => {
    if (!selectedIncidentId) return;
    setActionLoading(true);
    try {
      if (type === 'acknowledge' && onAcknowledgeIncident) {
        await onAcknowledgeIncident(selectedIncidentId, analystNoteInput || 'Acknowledged by operator');
      } else if (type === 'resolve' && onResolveIncident) {
        await onResolveIncident(selectedIncidentId, resolutionInput || 'Resolved by operator', analystNoteInput);
      } else if (type === 'close' && onCloseIncident) {
        await onCloseIncident(selectedIncidentId, resolutionInput || 'Closed by operator', analystNoteInput);
      } else if (type === 'reopen' && onReopenIncident) {
        await onReopenIncident(selectedIncidentId, analystNoteInput || 'Reopened by operator');
      }
      const [detail, timeline, summary] = await Promise.all([
        fetchIncidentDetail(selectedIncidentId),
        fetchIncidentTimeline(selectedIncidentId),
        fetchIncidentSummary(selectedIncidentId),
      ]);
      if (detail) setIncidentDetail(detail);
      if (timeline) setIncidentTimeline(timeline);
      if (summary) setIncidentSummaryReport(summary);
    } catch (err) {
      console.error('Error performing incident action:', err);
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="dashboard-container">
      <div className="dashboard-grid">
        {/* 1. System Status */}
        <DashboardCard title="System Status" icon={Server}>
          <div className="status-detail-list">
            <div className="detail-item">
              <span className="detail-label">Backend Service:</span>
              <span className={`badge ${apiStatus.connected ? 'badge-success' : 'badge-danger'}`}>
                {apiStatus.connected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Service Name:</span>
              <span className="detail-value">{apiStatus.data?.service || 'N/A'}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Socket.IO Stream:</span>
              <span className={`badge ${socketConnected ? 'badge-success' : 'badge-danger'}`}>
                {socketConnected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Capture Interface:</span>
              <span className="detail-value">{trafficMetrics?.interface || 'Auto'}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Capture Status:</span>
              <span className={`badge ${isCaptureRunning ? 'badge-success' : isPermissionDenied ? 'badge-warning' : 'badge-danger'}`}>
                {trafficMetrics?.status ? trafficMetrics.status.toUpperCase() : 'STOPPED'}
              </span>
            </div>
          </div>
        </DashboardCard>

        {/* 2. Network Traffic (Live Metrics) */}
        <DashboardCard title="Network Traffic" icon={Activity}>
          {!trafficMetrics ? (
            <div className="placeholder-state">
              <Activity size={36} className="placeholder-icon pulse" />
              <p className="placeholder-text">Waiting for network traffic telemetry</p>
            </div>
          ) : (
            <div className="traffic-metrics-container">
              {isPermissionDenied && (
                <div className="notice-banner warning">
                  <AlertCircle size={16} />
                  <span>Raw capture inactive: requires CAP_NET_RAW / elevated privileges</span>
                </div>
              )}

              <div className="metrics-grid">
                <div className="metric-box">
                  <span className="metric-label">Rate (pps)</span>
                  <span className="metric-value">{trafficMetrics.packets_per_sec.toFixed(1)}</span>
                </div>
                <div className="metric-box">
                  <span className="metric-label">Throughput</span>
                  <span className="metric-value">{formatBytes(trafficMetrics.bytes_per_sec)}/s</span>
                </div>
                <div className="metric-box">
                  <span className="metric-label">Total Packets</span>
                  <span className="metric-value">{trafficMetrics.total_packets.toLocaleString()}</span>
                </div>
                <div className="metric-box">
                  <span className="metric-label">Total Volume</span>
                  <span className="metric-value">{formatBytes(trafficMetrics.total_bytes)}</span>
                </div>
              </div>

              {/* Protocol breakdown */}
              <div className="protocol-breakdown">
                <div className="proto-pill">
                  <span className="proto-name">TCP</span>
                  <span className="proto-count">{trafficMetrics.tcp_packets.toLocaleString()}</span>
                </div>
                <div className="proto-pill">
                  <span className="proto-name">UDP</span>
                  <span className="proto-count">{trafficMetrics.udp_packets.toLocaleString()}</span>
                </div>
                <div className="proto-pill">
                  <span className="proto-name">ICMP</span>
                  <span className="proto-count">{trafficMetrics.icmp_packets.toLocaleString()}</span>
                </div>
                <div className="proto-pill">
                  <span className="proto-name">ARP</span>
                  <span className="proto-count">{(trafficMetrics.arp_packets || networkStatus?.arp?.stats?.total_arp_packets || 0).toLocaleString()}</span>
                </div>
                <div className="proto-pill">
                  <span className="proto-name">Other</span>
                  <span className="proto-count">{trafficMetrics.other_packets.toLocaleString()}</span>
                </div>
              </div>

              {/* Live Rate Chart */}
              {trafficHistory.length > 1 ? (
                <div className="traffic-chart-wrapper">
                  <div className="chart-header">
                    <span className="chart-title">Live Packets / Sec</span>
                  </div>
                  <ResponsiveContainer width="100%" height={90}>
                    <AreaChart data={trafficHistory} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
                      <defs>
                        <linearGradient id="ppsGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="time" hide={true} />
                      <YAxis stroke="#64748b" fontSize={10} domain={['auto', 'auto']} />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#0b0f19', borderColor: '#1e293b', fontSize: '12px' }}
                        labelStyle={{ color: '#94a3b8' }}
                      />
                      <Area 
                        type="monotone" 
                        dataKey="pps" 
                        stroke="#06b6d4" 
                        strokeWidth={2}
                        fillOpacity={1} 
                        fill="url(#ppsGradient)" 
                        isAnimationActive={false}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="empty-chart-notice">
                  <span>Waiting for traffic samples on {trafficMetrics.interface || 'interface'}...</span>
                </div>
              )}
            </div>
          )}
        </DashboardCard>

        {/* 3. Live Security Alerts */}
        <DashboardCard title={`Live Security Alerts (${alerts.length})`} icon={AlertTriangle}>
          {alerts.length === 0 ? (
            <div className="placeholder-state">
              <ShieldAlert size={36} className="placeholder-icon" />
              <p className="placeholder-text">No security events detected</p>
            </div>
          ) : (
            <div className="alerts-container">
              <div className="alerts-scroll-list">
                {alerts.map((alert) => (
                  <div key={alert.event_id} className={`alert-item severity-${alert.severity.toLowerCase()}`}>
                    <div className="alert-item-header">
                      <div className="alert-badges">
                        <span className={`badge badge-severity-${alert.severity.toLowerCase()}`}>
                          {alert.severity}
                        </span>
                        <span className="badge badge-rule">
                          {alert.detection_type}
                        </span>
                      </div>
                      <span className="alert-timestamp">
                        <Clock size={12} />
                        {formatAlertTime(alert.timestamp)}
                      </span>
                    </div>

                    <div className="alert-item-body">
                      <div className="alert-ip-route">
                        <span className="ip-source">{alert.source_ip || 'local host'}</span>
                        {alert.destination_ip && (
                          <>
                            <ArrowRight size={12} className="ip-arrow" />
                            <span className="ip-target">
                              {alert.destination_ip}
                              {alert.destination_port ? `:${alert.destination_port}` : ''}
                            </span>
                          </>
                        )}
                      </div>
                      <p className="alert-description">{alert.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </DashboardCard>

        {/* 4. Anomaly Detection (Isolation Forest) */}
        <DashboardCard title="Anomaly Detection (Isolation Forest)" icon={Brain}>
          {!mlStatus ? (
            <div className="placeholder-state">
              <Brain size={36} className="placeholder-icon pulse" />
              <p className="placeholder-text">Waiting for ML anomaly telemetry</p>
            </div>
          ) : (
            <div className="ml-card-container">
              <div className="ml-header-status">
                <span className="detail-label">Model Status:</span>
                <span className={`badge ${
                  mlStatus.model_status === 'READY' ? 'badge-success' :
                  mlStatus.model_status === 'COLLECTING_BASELINE' ? 'badge-info' :
                  mlStatus.model_status === 'ERROR' ? 'badge-danger' : 'badge-neutral'
                }`}>
                  {mlStatus.model_status}
                </span>
              </div>

              {mlStatus.model_status === 'COLLECTING_BASELINE' && (
                <div className="ml-baseline-progress">
                  <div className="progress-header">
                    <span>Baseline Profile Collection</span>
                    <span className="progress-percent">
                      {mlStatus.baseline_samples_collected} / {mlStatus.baseline_target_samples}
                    </span>
                  </div>
                  <div className="progress-track">
                    <div 
                      className="progress-bar-fill" 
                      style={{ 
                        width: `${Math.min(100, Math.round((mlStatus.baseline_samples_collected / Math.max(1, mlStatus.baseline_target_samples)) * 100))}%` 
                      }}
                    />
                  </div>
                  <span className="detail-value" style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                    Gathering normal traffic characteristics before enabling unsupervised outlier detection.
                  </span>
                </div>
              )}

              <div className="metrics-grid">
                <div className="metric-box">
                  <span className="metric-label">Latest Prediction</span>
                  <span className={`metric-value ${mlStatus.latest_prediction === 'ANOMALY' ? 'score-badge-anomaly' : 'score-badge-normal'}`}>
                    {mlStatus.latest_prediction}
                  </span>
                </div>
                <div className="metric-box">
                  <span className="metric-label">Anomaly Score</span>
                  <span className="metric-value">
                    {typeof mlStatus.latest_anomaly_score === 'number' ? mlStatus.latest_anomaly_score.toFixed(4) : '0.0000'}
                  </span>
                </div>
                <div className="metric-box">
                  <span className="metric-label">Anomalies Detected</span>
                  <span className="metric-value">{mlStatus.total_anomalies_detected || 0}</span>
                </div>
                <div className="metric-box">
                  <span className="metric-label">Window Size</span>
                  <span className="metric-value">{mlStatus.window_seconds ? `${mlStatus.window_seconds}s` : '5s'}</span>
                </div>
              </div>

              {mlMetrics?.window_history && mlMetrics.window_history.length > 1 ? (
                <div className="traffic-chart-wrapper">
                  <div className="chart-header">
                    <span className="chart-title">Window Anomaly Score Trend (Threshold = 0.5)</span>
                  </div>
                  <ResponsiveContainer width="100%" height={90}>
                    <AreaChart 
                      data={mlMetrics.window_history.map((w, i) => ({
                        idx: i,
                        score: w.anomaly_score,
                      }))} 
                      margin={{ top: 5, right: 5, left: -25, bottom: 0 }}
                    >
                      <defs>
                        <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0.0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="idx" hide={true} />
                      <YAxis stroke="#64748b" fontSize={10} domain={[0.0, 1.0]} />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#0b0f19', borderColor: '#1e293b', fontSize: '12px' }}
                        labelStyle={{ color: '#94a3b8' }}
                      />
                      <ReferenceLine y={0.5} stroke="#ef4444" strokeDasharray="3 3" />
                      <Area 
                        type="monotone" 
                        dataKey="score" 
                        stroke="#8b5cf6" 
                        strokeWidth={2}
                        fillOpacity={1} 
                        fill="url(#scoreGradient)" 
                        isAnimationActive={false}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              ) : null}
            </div>
          )}
        </DashboardCard>

        {/* 5. Composite Risk Engine */}
        <DashboardCard title="Composite Risk Engine" icon={ShieldCheck}>
          {!latestRisk ? (
            <div className="placeholder-state">
              <ShieldCheck size={36} className="placeholder-icon" />
              <p className="placeholder-text">Waiting for threat assessments</p>
            </div>
          ) : (
            <div className="risk-card-container">
              <div className="ml-header-status">
                <span className="detail-label">Current Threat Level:</span>
                <span className={`badge ${getRiskBadgeClass(latestRisk.risk_level)}`}>
                  {latestRisk.risk_level}
                </span>
              </div>

              <div className="metrics-grid">
                <div className="metric-box">
                  <span className="metric-label">Combined Score</span>
                  <span className="metric-value">{latestRisk.combined_score.toFixed(4)}</span>
                </div>
                <div className="metric-box">
                  <span className="metric-label">Action</span>
                  <span className={`metric-value ${latestRisk.recommended_action === 'block' ? 'score-badge-anomaly' : 'score-badge-normal'}`}>
                    {latestRisk.recommended_action.toUpperCase()}
                  </span>
                </div>
                <div className="metric-box">
                  <span className="metric-label">Source IP</span>
                  <span className="metric-value" style={{ fontSize: '0.95rem' }}>{latestRisk.source_ip}</span>
                </div>
                <div className="metric-box">
                  <span className="metric-label">Total Evaluated</span>
                  <span className="metric-value">{riskStats?.total_assessments || riskAssessments.length}</span>
                </div>
              </div>

              {/* Network + Host Correlation Callout */}
              {latestRisk.evidence?.correlated && (
                <div className="correlation-callout">
                  <span className="correlation-badge">CORRELATED ATTACK</span>
                  <span className="correlation-text">
                    {latestRisk.evidence.correlation_reason || 'Cross-domain network reconnaissance and host authentication activity detected.'}
                  </span>
                </div>
              )}

              {/* Score formula breakdown */}
              <div className="risk-breakdown-bar">
                <div className="breakdown-row">
                  <span>Rule Contribution (65%):</span>
                  <span className="breakdown-val">{(0.65 * latestRisk.rule_score).toFixed(3)}</span>
                </div>
                <div className="breakdown-row">
                  <span>ML Anomaly Contribution (35%):</span>
                  <span className="breakdown-val">{(0.35 * latestRisk.ml_anomaly_score).toFixed(3)}</span>
                </div>
                {latestRisk.evidence?.correlation_boost > 0 && (
                  <div className="breakdown-row" style={{ color: '#f97316' }}>
                    <span>Cross-Domain Boost:</span>
                    <span className="breakdown-val" style={{ color: '#f97316' }}>+{latestRisk.evidence.correlation_boost.toFixed(2)}</span>
                  </div>
                )}
              </div>

              {/* Recent assessments mini list */}
              <div className="risk-scroll-list">
                {riskAssessments.slice(0, 5).map((r) => (
                  <div key={r.assessment_id} className="risk-item">
                    <div className="risk-item-left">
                      <span className={`badge ${getRiskBadgeClass(r.risk_level)}`} style={{ padding: '0.15rem 0.4rem', fontSize: '0.65rem' }}>
                        {r.risk_level}
                      </span>
                      <span className="risk-item-ip">{r.source_ip}</span>
                    </div>
                    <span className="detail-value" style={{ fontSize: '0.75rem' }}>
                      Score: {r.combined_score.toFixed(2)} → {r.recommended_action}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </DashboardCard>

        {/* 6. Firewall Mitigation & Blocked IPs */}
        <DashboardCard title={`Firewall Mitigation (${blockedIPs.length})`} icon={Shield}>
          <div className="firewall-card-container">
            <div className="ml-header-status">
              <span className="detail-label">iptables Integration:</span>
              <div style={{ display: 'flex', gap: '0.4rem' }}>
                <span className={`badge ${firewallStatus?.enabled ? 'badge-success' : 'badge-neutral'}`}>
                  {firewallStatus?.enabled ? 'ENABLED' : 'DISABLED'}
                </span>
                <span className={`badge ${firewallStatus?.auto_block ? 'badge-critical' : 'badge-neutral'}`}>
                  {firewallStatus?.auto_block ? 'AUTO-BLOCK ON' : 'AUTO-BLOCK OFF'}
                </span>
              </div>
            </div>

            <div className="detail-item" style={{ fontSize: '0.75rem' }}>
              <span className="detail-label">Managed Chain:</span>
              <span className="detail-value">{firewallStatus?.chain || 'NETSENTINEL'}</span>
              <span className="detail-label" style={{ marginLeft: '1rem' }}>Mode:</span>
              <span className="detail-value">{firewallStatus?.dry_run ? 'Dry-Run (Simulated)' : 'Live Kernel'}</span>
            </div>

            {blockedIPs.length === 0 ? (
              <div className="placeholder-state" style={{ padding: '1rem 0' }}>
                <Lock size={32} className="placeholder-icon" />
                <p className="placeholder-text">No actively blocked IP addresses</p>
              </div>
            ) : (
              <div className="blocked-ip-list">
                {blockedIPs.map((blk) => (
                  <div key={blk.ip} className="blocked-ip-item">
                    <div className="blocked-ip-info">
                      <span className="blocked-ip-addr">{blk.ip}</span>
                      <span className="blocked-ip-reason">{blk.reason}</span>
                      {blk.expires_at && (
                        <span className="blocked-ip-reason">
                          Expires: {new Date(blk.expires_at * 1000).toLocaleTimeString()}
                        </span>
                      )}
                    </div>
                    {onUnblock && (
                      <button 
                        className="btn-unblock"
                        onClick={() => onUnblock(blk.ip)}
                        title="Unblock IP"
                      >
                        Unblock
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </DashboardCard>

        {/* 7. Host Intrusion Detection (HIDS) */}
        <DashboardCard title="Host Intrusion Detection (HIDS)" icon={Terminal}>
          {!hostStatus ? (
            <div className="placeholder-state">
              <Terminal size={36} className="placeholder-icon pulse" />
              <p className="placeholder-text">Waiting for host security telemetry</p>
            </div>
          ) : (
            <div className="host-sec-container">
              {/* SSH Authentication Monitoring */}
              <div className="host-section-block">
                <div className="host-block-title">
                  <span>SSH Auth Monitoring</span>
                  <span className={`badge ${
                    hostStatus.ssh_detector?.status === 'RUNNING' ? 'badge-success' :
                    hostStatus.ssh_detector?.status === 'NOT_FOUND' ? 'badge-warning' :
                    hostStatus.ssh_detector?.status === 'PERMISSION_DENIED' ? 'badge-danger' : 'badge-neutral'
                  }`}>
                    {hostStatus.ssh_detector?.status || 'UNKNOWN'}
                  </span>
                </div>
                <div className="host-stat-row">
                  <span>Log Source:</span>
                  <span className="host-stat-val" style={{ fontSize: '0.7rem' }}>
                    {hostStatus.ssh_detector?.log_path ? hostStatus.ssh_detector.log_path.split('/').slice(-2).join('/') : 'Auto-detect'}
                  </span>
                </div>
                <div className="host-stat-row">
                  <span>Auth Failures:</span>
                  <span className="host-stat-val">{hostStatus.ssh_detector?.total_failures || 0}</span>
                </div>
                <div className="host-stat-row">
                  <span>Brute-Force Detections:</span>
                  <span className="host-stat-val" style={{ color: (hostStatus.ssh_detector?.total_brute_force_detected || 0) > 0 ? 'var(--status-red)' : 'inherit' }}>
                    {hostStatus.ssh_detector?.total_brute_force_detected || 0}
                  </span>
                </div>
                <div className="host-stat-row">
                  <span>Tracked Attacker IPs:</span>
                  <span className="host-stat-val">{hostStatus.ssh_detector?.tracked_sources_count || 0}</span>
                </div>
              </div>

              {/* Host Process Monitor */}
              <div className="host-section-block">
                <div className="host-block-title">
                  <span>Process Integrity Monitor</span>
                  <span className={`badge ${
                    hostStatus.process_monitor?.status === 'RUNNING' ? 'badge-success' : 'badge-neutral'
                  }`}>
                    {hostStatus.process_monitor?.status || 'UNKNOWN'}
                  </span>
                </div>
                <div className="host-stat-row">
                  <span>Baseline Active PIDs:</span>
                  <span className="host-stat-val">{hostStatus.process_monitor?.baseline_pids_count || 0}</span>
                </div>
                <div className="host-stat-row">
                  <span>Periodic Integrity Scans:</span>
                  <span className="host-stat-val">{hostStatus.process_monitor?.total_scans || 0}</span>
                </div>
                <div className="host-stat-row">
                  <span>Suspicious Processes:</span>
                  <span className="host-stat-val" style={{ color: (hostStatus.process_monitor?.suspicious_processes_detected || 0) > 0 ? 'var(--status-red)' : 'inherit' }}>
                    {hostStatus.process_monitor?.suspicious_processes_detected || 0}
                  </span>
                </div>
                <div className="host-stat-row">
                  <span>Visible System PIDs:</span>
                  <span className="host-stat-val">{hostStatus.process_monitor?.visible_processes || 0}</span>
                </div>
              </div>
            </div>
          )}
        </DashboardCard>

        {/* 8. Advanced Network Threat Detection (ARP & ICMP Sweeps) */}
        <DashboardCard title="Advanced Network Threats (ARP & ICMP)" icon={Radio}>
          <div className="host-sec-container">
            {/* ARP Spoofing & Poisoning Monitor */}
            <div className="host-section-block">
              <div className="host-block-title">
                <span>ARP Spoofing Monitor</span>
                <span className={`badge ${networkStatus?.arp?.enabled ? 'badge-success' : 'badge-neutral'}`}>
                  {networkStatus?.arp?.enabled ? 'ACTIVE' : 'ACTIVE'}
                </span>
              </div>
              <div className="host-stat-row">
                <span>Tracked IP-MAC Bindings:</span>
                <span className="host-stat-val">{networkStatus?.arp?.tracked_ips_count ?? arpMappings.length}</span>
              </div>
              <div className="host-stat-row">
                <span>ARP Spoofing Alerts:</span>
                <span className="host-stat-val" style={{ color: (networkStatus?.arp?.stats?.spoofing_alerts || stats['ARP_SPOOFING'] || 0) > 0 ? 'var(--status-red)' : 'inherit' }}>
                  {networkStatus?.arp?.stats?.spoofing_alerts ?? (stats['ARP_SPOOFING'] || 0)}
                </span>
              </div>
              <div className="host-stat-row">
                <span>Identity Conflict Alerts:</span>
                <span className="host-stat-val" style={{ color: (networkStatus?.arp?.stats?.conflict_alerts || stats['ARP_IDENTITY_CONFLICT'] || 0) > 0 ? 'var(--status-yellow)' : 'inherit' }}>
                  {networkStatus?.arp?.stats?.conflict_alerts ?? (stats['ARP_IDENTITY_CONFLICT'] || 0)}
                </span>
              </div>
              <div className="host-stat-row">
                <span>Conflict Threshold:</span>
                <span className="host-stat-val">{networkStatus?.arp?.conflict_threshold || 3} IPs / MAC</span>
              </div>
              <div className="host-stat-row">
                <span>State Timeout / Cooldown:</span>
                <span className="host-stat-val">
                  {networkStatus?.arp?.state_timeout_sec || 300}s / {networkStatus?.arp?.cooldown_sec || 60}s
                </span>
              </div>
            </div>

            {/* ICMP Sweep Detection */}
            <div className="host-section-block">
              <div className="host-block-title">
                <span>ICMP Sweep Detection</span>
                <span className="badge badge-success">
                  {networkStatus?.icmp_sweep?.enabled ? 'ACTIVE' : 'ACTIVE'}
                </span>
              </div>
              <div className="host-stat-row">
                <span>Sweep Time Window:</span>
                <span className="host-stat-val">{networkStatus?.icmp_sweep?.window_sec || 10}s</span>
              </div>
              <div className="host-stat-row">
                <span>Unique Target Threshold:</span>
                <span className="host-stat-val">{networkStatus?.icmp_sweep?.threshold || 10} hosts</span>
              </div>
              <div className="host-stat-row">
                <span>ICMP Sweep Alerts:</span>
                <span className="host-stat-val" style={{ color: (stats['ICMP_SWEEP'] || 0) > 0 ? 'var(--status-yellow)' : 'inherit' }}>
                  {stats['ICMP_SWEEP'] || 0}
                </span>
              </div>
              <div className="host-stat-row">
                <span>Tracked Probing Sources:</span>
                <span className="host-stat-val">{networkStatus?.icmp_sweep?.tracked_sources || 0}</span>
              </div>
              <div className="host-stat-row">
                <span>Alert Cooldown:</span>
                <span className="host-stat-val">{networkStatus?.icmp_sweep?.cooldown_sec || 60}s</span>
              </div>
            </div>
          </div>

          {arpMappings && arpMappings.length > 0 && (
            <div style={{ marginTop: '0.75rem', borderTop: '1px solid var(--border-color)', paddingTop: '0.5rem' }}>
              <span style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600 }}>Active ARP Table Bindings (Latest {Math.min(5, arpMappings.length)}):</span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', marginTop: '0.35rem' }}>
                {arpMappings.slice(0, 5).map((m) => (
                  <div key={m.ip} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', padding: '0.2rem 0.4rem', backgroundColor: '#0f172a', borderRadius: '4px', border: '1px solid #1e293b' }}>
                    <span style={{ fontFamily: 'monospace', color: '#38bdf8' }}>{m.ip}</span>
                    <span style={{ fontFamily: 'monospace', color: '#a78bfa' }}>{m.mac}</span>
                    <span style={{ color: '#64748b' }}>{m.claims_count || 1} claims</span>
                    {m.is_trusted && <span className="badge badge-success" style={{ fontSize: '0.6rem', padding: '1px 4px' }}>TRUSTED</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </DashboardCard>

        {/* 9. File Integrity Monitoring (FIM) (Phase 10) */}
        <DashboardCard
          title="File Integrity Monitoring (FIM)"
          icon={FileText}
          actions={
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <button
                className="btn-refresh"
                style={{ fontSize: '0.7rem', padding: '0.2rem 0.5rem' }}
                onClick={() => onRefreshFim && onRefreshFim()}
                title="Refresh FIM Status"
              >
                <RotateCcw size={12} /> Refresh
              </button>
              <button
                className="btn-refresh"
                style={{ fontSize: '0.7rem', padding: '0.2rem 0.5rem', borderColor: 'var(--accent-blue)', color: 'var(--accent-blue)' }}
                onClick={async () => {
                  if (window.confirm("Re-establish baseline for all monitored paths? This will update the expected cryptographic hashes to current state.")) {
                    if (onFimRebaseline) await onFimRebaseline();
                  }
                }}
                title="Rebuild Integrity Baseline"
              >
                <CheckCircle2 size={12} /> Re-baseline
              </button>
            </div>
          }
        >
          {!fimStatus ? (
            <div className="placeholder-state">
              <FileText size={36} className="placeholder-icon pulse" />
              <p className="placeholder-text">Waiting for File Integrity Monitoring status...</p>
            </div>
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
                  <div className="fim-stat-sub">SHA-256 / identity diffs</div>
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
                  <div className="fim-stat-sub">Permission boundaries</div>
                </div>
              </div>

              {/* Scan telemetry banner */}
              <div className="fim-meta-banner">
                <span><strong>Scan Interval:</strong> {fimStatus.interval_seconds}s</span>
                <span><strong>Last Scan:</strong> {fimStatus.last_scan_at ? formatFullTime(fimStatus.last_scan_at) : 'In progress...'}</span>
                <span><strong>Last Alert:</strong> {fimStatus.last_change_at ? formatFullTime(fimStatus.last_change_at) : 'None'}</span>
                {fimStatus.last_error && <span style={{ color: 'var(--status-red)' }}><strong>Error:</strong> {fimStatus.last_error}</span>}
              </div>

              {/* Recent FIM Events Table */}
              <div className="fim-events-wrapper">
                <div className="fim-events-title">
                  <span>Recent Integrity Events</span>
                  <span style={{ color: '#94a3b8', fontSize: '0.7rem' }}>Showing latest recorded events</span>
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
                      {(!fimEvents || fimEvents.length === 0) ? (
                        <tr>
                          <td colSpan={5} className="history-empty-row">
                            No integrity deviations recorded. Monitored files match expected baselines.
                          </td>
                        </tr>
                      ) : (
                        fimEvents.slice(0, 10).map((ev, idx) => {
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

        {/* 10. System Resources (Phase 6: Real Host Telemetry) */}
        <DashboardCard title="System Resources" icon={Cpu}>

          {!hostTelemetry ? (
            <div className="placeholder-state">
              <Cpu size={36} className="placeholder-icon pulse" />
              <p className="placeholder-text">Waiting for host system telemetry</p>
            </div>
          ) : (
            <div className="telemetry-card-container">
              {/* Gauges for CPU, Memory, Disk */}
              <div className="resource-gauges">
                {/* CPU */}
                <div className="resource-gauge-item">
                  <div className="gauge-header">
                    <span>CPU Utilization</span>
                    <span className="gauge-value">{hostTelemetry.cpu_percent.toFixed(1)}%</span>
                  </div>
                  <div className="gauge-track">
                    <div 
                      className={`gauge-fill cpu ${hostTelemetry.cpu_percent > 90 ? 'danger' : hostTelemetry.cpu_percent > 75 ? 'warning' : ''}`}
                      style={{ width: `${Math.min(100, Math.max(0, hostTelemetry.cpu_percent))}%` }}
                    />
                  </div>
                </div>

                {/* RAM */}
                <div className="resource-gauge-item">
                  <div className="gauge-header">
                    <span>RAM Memory</span>
                    <span className="gauge-value">
                      {hostTelemetry.memory_percent.toFixed(1)}% ({formatBytes(hostTelemetry.memory_used_bytes)} / {formatBytes(hostTelemetry.memory_used_bytes + hostTelemetry.memory_available_bytes)})
                    </span>
                  </div>
                  <div className="gauge-track">
                    <div 
                      className={`gauge-fill mem ${hostTelemetry.memory_percent > 90 ? 'danger' : hostTelemetry.memory_percent > 80 ? 'warning' : ''}`}
                      style={{ width: `${Math.min(100, Math.max(0, hostTelemetry.memory_percent))}%` }}
                    />
                  </div>
                </div>

                {/* Disk */}
                <div className="resource-gauge-item">
                  <div className="gauge-header">
                    <span>Disk Space</span>
                    <span className="gauge-value">
                      {hostTelemetry.disk_percent.toFixed(1)}% ({formatBytes(hostTelemetry.disk_used_bytes)} used)
                    </span>
                  </div>
                  <div className="gauge-track">
                    <div 
                      className={`gauge-fill disk ${hostTelemetry.disk_percent > 90 ? 'danger' : hostTelemetry.disk_percent > 80 ? 'warning' : ''}`}
                      style={{ width: `${Math.min(100, Math.max(0, hostTelemetry.disk_percent))}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* Subgrid: OS Load & Host Network Throughput */}
              <div className="telemetry-subgrid">
                <div className="telemetry-mini-stat">
                  <span className="mini-stat-label">OS Load (1m, 5m, 15m)</span>
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

              {/* Telemetry Trend Mini Chart */}
              {telemetryHistory.length > 1 ? (
                <div className="traffic-chart-wrapper">
                  <div className="chart-header">
                    <span className="chart-title">CPU (%) & RAM (%) Trend</span>
                  </div>
                  <ResponsiveContainer width="100%" height={80}>
                    <AreaChart data={telemetryHistory} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
                      <defs>
                        <linearGradient id="cpuGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                        </linearGradient>
                        <linearGradient id="ramGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0.0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="time" hide={true} />
                      <YAxis stroke="#64748b" fontSize={10} domain={[0, 100]} />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#0b0f19', borderColor: '#1e293b', fontSize: '12px' }}
                        labelStyle={{ color: '#94a3b8' }}
                      />
                      <Area 
                        type="monotone" 
                        dataKey="cpu" 
                        name="CPU %" 
                        stroke="#06b6d4" 
                        strokeWidth={1.5} 
                        fillOpacity={1} 
                        fill="url(#cpuGradient)" 
                        isAnimationActive={false} 
                      />
                      <Area 
                        type="monotone" 
                        dataKey="ram" 
                        name="RAM %" 
                        stroke="#8b5cf6" 
                        strokeWidth={1.5} 
                        fillOpacity={1} 
                        fill="url(#ramGradient)" 
                        isAnimationActive={false} 
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              ) : null}
            </div>
          )}
        </DashboardCard>

        {/* 8. Detection & Mitigation Statistics */}
        <DashboardCard title="Detection Statistics" icon={BarChart2}>
          {alerts.length === 0 && (!mlStatus || mlStatus.total_anomalies_detected === 0) && riskAssessments.length === 0 && !securitySummary?.total_events ? (
            <div className="placeholder-state">
              <BarChart2 size={36} className="placeholder-icon" />
              <p className="placeholder-text">Waiting for detection events</p>
            </div>
          ) : (
            <div className="detection-stats-container">
              <div className="stats-metric-row">
                <span className="stat-label">Total Events Recorded:</span>
                <span className="stat-number">
                  {securitySummary?.total_events || (alerts.length + (mlStatus?.total_anomalies_detected || 0))}
                </span>
              </div>
              <div className="stats-breakdown-list">
                <div className="stat-pill">
                  <span className="stat-pill-name">Port Scan</span>
                  <span className="stat-pill-val">
                    {securitySummary?.detection_types?.PORT_SCAN ?? stats.PORT_SCAN ?? 0}
                  </span>
                </div>
                <div className="stat-pill">
                  <span className="stat-pill-name">SYN Flood</span>
                  <span className="stat-pill-val">
                    {securitySummary?.detection_types?.SYN_FLOOD ?? stats.SYN_FLOOD ?? 0}
                  </span>
                </div>
                <div className="stat-pill">
                  <span className="stat-pill-name">NULL Scan</span>
                  <span className="stat-pill-val">
                    {securitySummary?.detection_types?.NULL_SCAN ?? stats.NULL_SCAN ?? 0}
                  </span>
                </div>
                <div className="stat-pill">
                  <span className="stat-pill-name">XMAS Scan</span>
                  <span className="stat-pill-val">
                    {securitySummary?.detection_types?.XMAS_SCAN ?? stats.XMAS_SCAN ?? 0}
                  </span>
                </div>
                <div className="stat-pill">
                  <span className="stat-pill-name">ML Anomaly</span>
                  <span className="stat-pill-val">
                    {securitySummary?.detection_types?.ANOMALY ?? mlStatus?.total_anomalies_detected ?? 0}
                  </span>
                </div>
                <div className="stat-pill">
                  <span className="stat-pill-name">SSH Failure</span>
                  <span className="stat-pill-val">
                    {securitySummary?.detection_types?.SSH_AUTH_FAILURE ?? stats.SSH_AUTH_FAILURE ?? 0}
                  </span>
                </div>
                <div className="stat-pill">
                  <span className="stat-pill-name">SSH Brute-Force</span>
                  <span className="stat-pill-val">
                    {securitySummary?.detection_types?.SSH_BRUTE_FORCE ?? stats.SSH_BRUTE_FORCE ?? 0}
                  </span>
                </div>
                <div className="stat-pill">
                  <span className="stat-pill-name">Suspicious Process</span>
                  <span className="stat-pill-val">
                    {securitySummary?.detection_types?.SUSPICIOUS_PROCESS ?? stats.SUSPICIOUS_PROCESS ?? 0}
                  </span>
                </div>
                <div className="stat-pill">
                  <span className="stat-pill-name">Blocked IPs</span>
                  <span className="stat-pill-val">{blockedIPs.length}</span>
                </div>
              </div>
            </div>
          )}
        </DashboardCard>

        {/* Phase 9: Incident Correlation & Investigation Section */}
        <div className="incident-section">
          <DashboardCard title={`Security Incidents & Investigation Workspace (${displayedIncidents.length} of ${incidents.length})`} icon={AlertOctagon}>
            <div className="telemetry-card-container">
              {/* Incident High-Level KPIs */}
              <div className="incident-kpis-grid">
                <div className="incident-kpi-card">
                  <span className="incident-kpi-label">Total Incidents</span>
                  <span className="incident-kpi-value">{incidentStats?.total_incidents ?? incidents.length}</span>
                </div>
                <div className="incident-kpi-card">
                  <span className="incident-kpi-label">Open / Active</span>
                  <span className="incident-kpi-value open">{incidentStats?.open ?? incidents.filter(i => i.status === 'OPEN').length}</span>
                </div>
                <div className="incident-kpi-card">
                  <span className="incident-kpi-label">Acknowledged</span>
                  <span className="incident-kpi-value" style={{ color: '#fbbf24' }}>
                    {incidentStats?.acknowledged ?? incidents.filter(i => i.status === 'ACKNOWLEDGED').length}
                  </span>
                </div>
                <div className="incident-kpi-card">
                  <span className="incident-kpi-label">Critical Severity</span>
                  <span className="incident-kpi-value critical">
                    {incidentStats?.severities?.CRITICAL ?? incidents.filter(i => i.severity === 'CRITICAL').length}
                  </span>
                </div>
                <div className="incident-kpi-card">
                  <span className="incident-kpi-label">Resolved / Closed</span>
                  <span className="incident-kpi-value resolved">
                    {((incidentStats?.resolved ?? 0) + (incidentStats?.closed ?? 0)) || incidents.filter(i => i.status === 'RESOLVED' || i.status === 'CLOSED').length}
                  </span>
                </div>
              </div>

              {/* Toolbar & Filters */}
              <div className="incident-toolbar">
                <div className="incident-filters">
                  <Filter size={14} color="#64748b" />
                  <select
                    className="history-filter-select"
                    value={incidentStatusFilter}
                    onChange={(e) => setIncidentStatusFilter(e.target.value)}
                  >
                    <option value="ALL">All Statuses</option>
                    <option value="OPEN">Open</option>
                    <option value="ACKNOWLEDGED">Acknowledged</option>
                    <option value="RESOLVED">Resolved</option>
                    <option value="CLOSED">Closed</option>
                  </select>

                  <select
                    className="history-filter-select"
                    value={incidentSeverityFilter}
                    onChange={(e) => setIncidentSeverityFilter(e.target.value)}
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>

                  <div className="incident-search-box">
                    <Search size={13} color="#64748b" />
                    <input
                      type="text"
                      className="incident-search-input"
                      placeholder="Search IP, Host, or ID..."
                      value={incidentSearchQuery}
                      onChange={(e) => setIncidentSearchQuery(e.target.value)}
                    />
                  </div>
                </div>

                {onRefreshIncidents && (
                  <button
                    className="btn-refresh"
                    onClick={() => onRefreshIncidents()}
                    title="Refresh Correlated Incidents"
                  >
                    <RotateCcw size={13} />
                    Refresh Incidents
                  </button>
                )}
              </div>

              {/* Incidents Table */}
              <div className="history-table-container">
                <table className="history-table">
                  <thead>
                    <tr>
                      <th>Incident ID</th>
                      <th>Title & Threat Vectors</th>
                      <th>Attacker / Target</th>
                      <th>Severity</th>
                      <th>Risk Score</th>
                      <th>Status</th>
                      <th>Events / FW</th>
                      <th>Last Seen</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayedIncidents.length === 0 ? (
                      <tr>
                        <td colSpan={9} className="history-empty-row">
                          No correlated incidents matching current criteria
                        </td>
                      </tr>
                    ) : (
                      displayedIncidents.map((inc) => (
                        <tr key={inc.incident_id}>
                          <td style={{ fontFamily: 'monospace', color: '#94a3b8', fontSize: '0.7rem' }}>
                            {inc.incident_id}
                          </td>
                          <td style={{ maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            <div style={{ fontWeight: 600, color: '#f8fafc', fontSize: '0.75rem' }}>
                              {inc.title}
                            </div>
                            <div style={{ display: 'flex', gap: '0.3rem', marginTop: '0.2rem', flexWrap: 'wrap' }}>
                              {(inc.detection_types || []).map((dt) => (
                                <span key={dt} className="badge badge-rule" style={{ fontSize: '0.6rem', padding: '0.1rem 0.35rem' }}>
                                  {dt}
                                </span>
                              ))}
                              {(inc.attack_domains || []).map((dom) => (
                                <span key={dom} style={{ fontSize: '0.6rem', padding: '0.1rem 0.35rem', backgroundColor: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', borderRadius: '3px' }}>
                                  {dom}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td style={{ fontFamily: 'monospace', color: '#38bdf8', fontWeight: 600 }}>
                            {inc.primary_source_ip || inc.correlation_key}
                          </td>
                          <td>
                            <span className={getRiskBadgeClass(inc.severity)} style={{ fontSize: '0.65rem' }}>
                              {inc.severity}
                            </span>
                          </td>
                          <td style={{ fontFamily: 'monospace', fontWeight: 600, color: inc.risk_score >= 0.8 ? '#f43f5e' : inc.risk_score >= 0.6 ? '#f97316' : '#38bdf8' }}>
                            {(inc.risk_score ?? 0).toFixed(2)}
                          </td>
                          <td>
                            <span className={getIncidentStatusBadgeClass(inc.status)}>
                              {inc.status}
                            </span>
                          </td>
                          <td style={{ fontSize: '0.7rem', color: '#94a3b8' }}>
                            {inc.event_count} ev / {inc.firewall_action_count} fw
                          </td>
                          <td style={{ color: '#94a3b8', fontSize: '0.7rem' }}>
                            {formatFullTime(inc.last_seen)}
                          </td>
                          <td>
                            <button
                              className="btn-investigate"
                              onClick={() => handleOpenInvestigate(inc.incident_id)}
                              title="Investigate Incident"
                            >
                              <Layers size={12} />
                              Investigate
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </DashboardCard>
        </div>

        {/* Phase 9: Deep Investigation Modal / Drawer */}
        {selectedIncidentId && (
          <div className="investigation-backdrop" onClick={() => setSelectedIncidentId(null)}>
            <div className="investigation-modal" onClick={(e) => e.stopPropagation()}>
              {/* Modal Header */}
              <div className="investigation-modal-header">
                <div className="modal-header-info">
                  <div className="modal-title-row">
                    <span className="modal-title">
                      {incidentDetail?.title || `Incident ${selectedIncidentId}`}
                    </span>
                    {incidentDetail && (
                      <>
                        <span className={getIncidentStatusBadgeClass(incidentDetail.status)}>
                          {incidentDetail.status}
                        </span>
                        <span className={getRiskBadgeClass(incidentDetail.severity)}>
                          {incidentDetail.severity}
                        </span>
                      </>
                    )}
                  </div>
                  <div className="modal-subtitle">
                    ID: {selectedIncidentId} | Target: {incidentDetail?.primary_source_ip || incidentDetail?.correlation_key || 'Unknown'} | Risk Score: {(incidentDetail?.risk_score ?? 0).toFixed(2)}
                  </div>
                </div>
                <button
                  className="modal-close-btn"
                  onClick={() => setSelectedIncidentId(null)}
                  title="Close Investigation Modal"
                >
                  <X size={18} />
                </button>
              </div>

              {/* Correlation Reason Callout */}
              {incidentDetail?.correlation_reason && (
                <div style={{ margin: '0.75rem 1.25rem 0', padding: '0.6rem 0.85rem', backgroundColor: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.3)', borderRadius: '6px', fontSize: '0.75rem', color: '#bae6fd', lineHeight: 1.4 }}>
                  <div style={{ fontWeight: 700, marginBottom: '0.2rem', color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                    <AlertCircle size={14} /> Correlation Explanation
                  </div>
                  {incidentDetail.correlation_reason}
                </div>
              )}

              {/* Tabs Navigation */}
              <div className="investigation-tabs-nav">
                <button
                  className={`investigation-tab-btn ${modalTab === 'timeline' ? 'active' : ''}`}
                  onClick={() => setModalTab('timeline')}
                >
                  <Clock size={14} /> Unified Timeline ({incidentTimeline.length})
                </button>
                <button
                  className={`investigation-tab-btn ${modalTab === 'context' ? 'active' : ''}`}
                  onClick={() => setModalTab('context')}
                >
                  <Layers size={14} /> Attack Context & Vectors
                </button>
                <button
                  className={`investigation-tab-btn ${modalTab === 'evidence' ? 'active' : ''}`}
                  onClick={() => setModalTab('evidence')}
                >
                  <FileText size={14} /> Evidence Artifacts ({incidentDetail?.evidence?.length ?? 0})
                </button>
                <button
                  className={`investigation-tab-btn ${modalTab === 'report' ? 'active' : ''}`}
                  onClick={() => setModalTab('report')}
                >
                  <CheckCircle2 size={14} /> SOC Report Summary
                </button>
              </div>

              {/* Tab Contents */}
              <div className="investigation-modal-body">
                {modalTab === 'timeline' && (
                  <div className="timeline-container">
                    {incidentTimeline.length === 0 ? (
                      <div style={{ color: '#94a3b8', fontSize: '0.8rem', padding: '1rem', textAlign: 'center' }}>
                        Loading timeline events...
                      </div>
                    ) : (
                      incidentTimeline.map((item, idx) => (
                        <div
                          key={idx}
                          className={`timeline-item ${item.type === 'MILESTONE' ? 'milestone' : item.type === 'FIREWALL_ACTION' ? 'firewall' : ''}`}
                        >
                          <div className="timeline-top-row">
                            <span className="timeline-title">{item.title}</span>
                            <span className="timeline-time">{formatFullTime(item.timestamp)}</span>
                          </div>
                          <div className="timeline-desc">{item.description}</div>
                          {item.metadata?.change_type ? (
                            <div className="fim-timeline-evidence-box">
                              <div style={{ color: '#38bdf8', fontFamily: 'monospace' }}>Path: {item.metadata.path}</div>
                              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginTop: '0.2rem' }}>
                                <span className="badge badge-warning" style={{ fontSize: '0.65rem' }}>{item.metadata.change_type}</span>
                                {item.metadata.previous_sha256 && (
                                  <span style={{ fontSize: '0.65rem', color: '#94a3b8' }}>
                                    Hash: <code>{item.metadata.previous_sha256.substring(0, 10)}...</code> &rarr; <code>{(item.metadata.current_sha256 || 'None').substring(0, 10)}...</code>
                                  </span>
                                )}
                              </div>
                            </div>
                          ) : item.metadata && Object.keys(item.metadata).length > 0 && (
                            <pre className="evidence-meta-pre">
                              {JSON.stringify(item.metadata, null, 2)}
                            </pre>
                          )}
                        </div>

                      ))
                    )}
                  </div>
                )}

                {modalTab === 'context' && incidentDetail && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.8rem' }}>
                    <div className="host-section-block">
                      <div className="host-block-title">Attacker & Target Identification</div>
                      <div className="host-stat-row">
                        <span>Correlation Key:</span>
                        <span className="host-stat-val">{incidentDetail.correlation_key}</span>
                      </div>
                      <div className="host-stat-row">
                        <span>Primary Source IP:</span>
                        <span className="host-stat-val">{incidentDetail.primary_source_ip || 'None (Host-Internal Identity)'}</span>
                      </div>
                      <div className="host-stat-row">
                        <span>Attack Domains:</span>
                        <span className="host-stat-val">{(incidentDetail.attack_domains || []).join(', ') || 'network'}</span>
                      </div>
                      <div className="host-stat-row">
                        <span>Detection Vectors:</span>
                        <span className="host-stat-val">{(incidentDetail.detection_types || []).join(', ')}</span>
                      </div>
                    </div>

                    <div className="host-section-block">
                      <div className="host-block-title">Deterministic Risk Profile</div>
                      <div className="host-stat-row">
                        <span>Risk Score:</span>
                        <span className="host-stat-val">{(incidentDetail.risk_score ?? 0).toFixed(4)}</span>
                      </div>
                      <div className="host-stat-row">
                        <span>Calculated Severity:</span>
                        <span className="host-stat-val">{incidentDetail.severity}</span>
                      </div>
                      <div className="host-stat-row">
                        <span>Correlated Alert Count:</span>
                        <span className="host-stat-val">{incidentDetail.event_count}</span>
                      </div>
                      <div className="host-stat-row">
                        <span>Mitigation Action Count:</span>
                        <span className="host-stat-val">{incidentDetail.firewall_action_count}</span>
                      </div>
                    </div>

                    {incidentDetail.analyst_note && (
                      <div className="host-section-block">
                        <div className="host-block-title">Analyst Notes</div>
                        <div style={{ color: '#cbd5e1', fontSize: '0.75rem' }}>{incidentDetail.analyst_note}</div>
                      </div>
                    )}
                  </div>
                )}

                {modalTab === 'evidence' && (
                  <div className="history-table-container">
                    <table className="history-table">
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Evidence Type</th>
                          <th>Detection / Action</th>
                          <th>Severity</th>
                          <th>Summary</th>
                          <th>Reference ID</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(incidentDetail?.evidence || []).length === 0 ? (
                          <tr>
                            <td colSpan={6} className="history-empty-row">No evidence items attached.</td>
                          </tr>
                        ) : (
                          (incidentDetail?.evidence || []).map((e) => (
                            <tr key={e.evidence_id}>
                              <td style={{ color: '#94a3b8', fontSize: '0.7rem' }}>{formatFullTime(e.timestamp)}</td>
                              <td><span className="badge badge-rule">{e.evidence_type}</span></td>
                              <td style={{ fontFamily: 'monospace', color: '#38bdf8' }}>{e.detection_type || e.metadata?.action || '-'}</td>
                              <td>
                                {e.severity ? (
                                  <span className={getRiskBadgeClass(e.severity)} style={{ fontSize: '0.65rem' }}>
                                    {e.severity}
                                  </span>
                                ) : '-'}
                              </td>
                              <td style={{ maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                {e.metadata?.change_type ? (
                                  <div>
                                    <div style={{ fontWeight: 600 }}>{e.summary}</div>
                                    <div style={{ fontSize: '0.65rem', color: '#94a3b8', fontFamily: 'monospace' }}>
                                      {e.metadata.path}
                                      {e.metadata.previous_sha256 && ` (${e.metadata.previous_sha256.substring(0, 8)}... → ${e.metadata.current_sha256?.substring(0, 8)}...)`}
                                    </div>
                                  </div>
                                ) : (
                                  e.summary
                                )}
                              </td>
                              <td style={{ fontFamily: 'monospace', color: '#64748b', fontSize: '0.65rem' }}>{e.reference_id}</td>

                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                )}

                {modalTab === 'report' && incidentSummaryReport && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.8rem' }}>
                    <div className="host-section-block">
                      <div className="host-block-title">Executive Incident Summary</div>
                      <div className="host-stat-row">
                        <span>First Seen (UTC):</span>
                        <span className="host-stat-val">{incidentSummaryReport.first_seen_iso || '-'}</span>
                      </div>
                      <div className="host-stat-row">
                        <span>Last Seen (UTC):</span>
                        <span className="host-stat-val">{incidentSummaryReport.last_seen_iso || '-'}</span>
                      </div>
                      <div className="host-stat-row">
                        <span>Attack Duration:</span>
                        <span className="host-stat-val">{incidentSummaryReport.duration_seconds} seconds</span>
                      </div>
                      <div className="host-stat-row">
                        <span>Attack Vectors:</span>
                        <span className="host-stat-val">{(incidentSummaryReport.attack_vectors || []).join(', ')}</span>
                      </div>
                      <div className="host-stat-row">
                        <span>Mitigations Applied:</span>
                        <span className="host-stat-val">{(incidentSummaryReport.mitigations_applied || []).length} action(s)</span>
                      </div>
                    </div>

                    {(incidentSummaryReport.mitigations_applied || []).length > 0 && (
                      <div className="host-section-block">
                        <div className="host-block-title">Mitigations Applied</div>
                        {incidentSummaryReport.mitigations_applied.map((m, idx) => (
                          <div key={idx} className="host-stat-row" style={{ padding: '0.2rem 0' }}>
                            <span style={{ color: '#f43f5e', fontWeight: 600 }}>{(m.action || 'action').toUpperCase()}</span>
                            <span>{m.summary} ({formatFullTime(m.timestamp)})</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Operator Action Controls */}
              <div className="investigation-actions-panel">
                <div className="action-inputs-row">
                  <input
                    type="text"
                    className="action-text-input"
                    placeholder="Add analyst investigation note..."
                    value={analystNoteInput}
                    onChange={(e) => setAnalystNoteInput(e.target.value)}
                  />
                  <input
                    type="text"
                    className="action-text-input"
                    placeholder="Resolution summary (e.g. Block applied, harmless scan dismissed)..."
                    value={resolutionInput}
                    onChange={(e) => setResolutionInput(e.target.value)}
                  />
                </div>

                <div className="action-buttons-row">
                  {incidentDetail?.status === 'OPEN' && (
                    <button
                      className="btn-action-ack"
                      disabled={actionLoading}
                      onClick={() => handleAction('acknowledge')}
                    >
                      Acknowledge Incident
                    </button>
                  )}

                  {incidentDetail?.status !== 'RESOLVED' && incidentDetail?.status !== 'CLOSED' && (
                    <button
                      className="btn-action-resolve"
                      disabled={actionLoading}
                      onClick={() => handleAction('resolve')}
                    >
                      Mark Resolved
                    </button>
                  )}

                  {incidentDetail?.status !== 'CLOSED' && (
                    <button
                      className="btn-action-close"
                      disabled={actionLoading}
                      onClick={() => handleAction('close')}
                    >
                      Close Incident
                    </button>
                  )}

                  {(incidentDetail?.status === 'RESOLVED' || incidentDetail?.status === 'CLOSED') && (
                    <button
                      className="btn-action-reopen"
                      disabled={actionLoading}
                      onClick={() => handleAction('reopen')}
                    >
                      Reopen Incident
                    </button>
                  )}

                  <span style={{ marginLeft: 'auto', fontSize: '0.7rem', color: '#94a3b8' }}>
                    Status: <strong style={{ color: '#f8fafc' }}>{incidentDetail?.status}</strong>
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 10. Security History & Activity Log (Phase 6) */}
        <div className="history-section">
          <DashboardCard title={`Security Event History (${displayedHistory.length} of ${historicalEvents.length})`} icon={History}>
            <div className="telemetry-card-container">
              <div className="history-card-header">
                <div className="history-filters">
                  <Filter size={14} color="#64748b" />
                  <select 
                    className="history-filter-select"
                    value={historyTypeFilter}
                    onChange={(e) => setHistoryTypeFilter(e.target.value)}
                  >
                    <option value="ALL">All Types</option>
                    <option value="PORT_SCAN">Port Scan</option>
                    <option value="SYN_FLOOD">SYN Flood</option>
                    <option value="NULL_SCAN">NULL Scan</option>
                    <option value="XMAS_SCAN">XMAS Scan</option>
                    <option value="ARP_SPOOFING">ARP Spoofing</option>
                    <option value="ARP_IDENTITY_CONFLICT">ARP Identity Conflict</option>
                    <option value="ICMP_SWEEP">ICMP Sweep</option>
                    <option value="ANOMALY">ML Anomaly</option>
                    <option value="SSH_AUTH_FAILURE">SSH Auth Failure</option>
                    <option value="SSH_BRUTE_FORCE">SSH Brute-Force</option>
                    <option value="SUSPICIOUS_PROCESS">Suspicious Process</option>
                  </select>

                  <select 
                    className="history-filter-select"
                    value={historySeverityFilter}
                    onChange={(e) => setHistorySeverityFilter(e.target.value)}
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>

                  <input 
                    type="text"
                    className="history-search-input"
                    placeholder="Search source IP..."
                    value={historySearchIP}
                    onChange={(e) => setHistorySearchIP(e.target.value)}
                  />
                </div>

                {onRefreshHistory && (
                  <button 
                    className="btn-refresh"
                    onClick={() => onRefreshHistory()}
                    title="Refresh persisted security history"
                  >
                    <RotateCcw size={13} />
                    Refresh
                  </button>
                )}
              </div>

              <div className="history-table-container">
                <table className="history-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Type</th>
                      <th>Severity</th>
                      <th>Source IP</th>
                      <th>Destination</th>
                      <th>Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayedHistory.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="history-empty-row">
                          No historical security events matching current criteria
                        </td>
                      </tr>
                    ) : (
                      displayedHistory.map((ev) => (
                        <tr key={ev.event_id}>
                          <td style={{ color: '#94a3b8', fontSize: '0.7rem' }}>
                            {formatFullTime(ev.timestamp)}
                          </td>
                          <td>
                            <span className="badge badge-rule" style={{ fontSize: '0.65rem' }}>
                              {ev.detection_type}
                            </span>
                          </td>
                          <td>
                            <span className={`badge badge-severity-${(ev.severity || 'low').toLowerCase()}`} style={{ fontSize: '0.65rem' }}>
                              {ev.severity}
                            </span>
                          </td>
                          <td style={{ fontFamily: 'monospace', color: '#38bdf8' }}>
                            {ev.source_ip || 'local host'}
                          </td>
                          <td style={{ fontFamily: 'monospace', color: '#94a3b8' }}>
                            {ev.destination_ip ? `${ev.destination_ip}${ev.destination_port ? `:${ev.destination_port}` : ''}` : '-'}
                          </td>
                          <td style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {ev.description}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </DashboardCard>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
