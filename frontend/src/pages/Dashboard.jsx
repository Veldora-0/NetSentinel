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
  Terminal
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, ReferenceLine } from 'recharts';
import { DashboardCard } from '../components/DashboardCard';

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

        {/* 8. System Resources (Phase 6: Real Host Telemetry) */}
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

        {/* 9. Security History & Activity Log (Phase 6) */}
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
