import React from 'react';
import { 
  Server, 
  AlertTriangle, 
  Activity, 
  ShieldAlert, 
  Cpu, 
  BarChart2,
  Radio,
  Wifi,
  AlertCircle
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';
import { DashboardCard } from '../components/DashboardCard';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export function Dashboard({ apiStatus, socketConnected, trafficMetrics, trafficHistory = [] }) {
  const isCaptureRunning = trafficMetrics?.status === 'running';
  const isPermissionDenied = trafficMetrics?.status === 'permission_denied';

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
        <DashboardCard title="Live Security Alerts" icon={AlertTriangle}>
          <div className="placeholder-state">
            <ShieldAlert size={36} className="placeholder-icon" />
            <p className="placeholder-text">No active alerts</p>
          </div>
        </DashboardCard>

        {/* 4. Blocked IPs */}
        <DashboardCard title="Blocked IPs" icon={ShieldAlert}>
          <div className="placeholder-state">
            <p className="placeholder-text">No blocked IPs</p>
          </div>
        </DashboardCard>

        {/* 5. System Resources */}
        <DashboardCard title="System Resources" icon={Cpu}>
          <div className="placeholder-state">
            <Cpu size={36} className="placeholder-icon" />
            <p className="placeholder-text">Waiting for telemetry</p>
          </div>
        </DashboardCard>

        {/* 6. Detection Statistics */}
        <DashboardCard title="Detection Statistics" icon={BarChart2}>
          <div className="placeholder-state">
            <BarChart2 size={36} className="placeholder-icon" />
            <p className="placeholder-text">Waiting for detection engine</p>
          </div>
        </DashboardCard>
      </div>
    </div>
  );
}
