import React, { useState, useEffect } from 'react';
import {
  Activity,
  Radio,
  AlertTriangle,
  RefreshCw,
  Search,
  Wifi,
  Layers,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
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
  fetchTrafficMetrics,
  fetchNetworkStatus,
  fetchARPMappings,
  fetchSecurityAlerts,
} from '../services/api';
import {
  formatNumber,
  formatBytes,
  formatRate,
  formatAlertTime,
  formatFullTime,
} from '../utils/formatters';

export function Network() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [trafficMetrics, setTrafficMetrics] = useState(null);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [networkStatus, setNetworkStatus] = useState(null);
  const [arpMappings, setArpMappings] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [arpSearch, setArpSearch] = useState('');

  const loadNetworkData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [metricsRes, netStatusRes, arpRes, alertsRes] = await Promise.allSettled([
        fetchTrafficMetrics(),
        fetchNetworkStatus(),
        fetchARPMappings(100),
        fetchSecurityAlerts(50),
      ]);

      if (metricsRes.status === 'fulfilled' && metricsRes.value) setTrafficMetrics(metricsRes.value);
      if (netStatusRes.status === 'fulfilled' && netStatusRes.value?.network) setNetworkStatus(netStatusRes.value.network);
      if (arpRes.status === 'fulfilled' && arpRes.value?.mappings) setArpMappings(arpRes.value.mappings);
      if (alertsRes.status === 'fulfilled' && Array.isArray(alertsRes.value)) setAlerts(alertsRes.value);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadNetworkData();
  }, []);

  // Socket.IO updates
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
      return updated.length > 30 ? updated.slice(-30) : updated;
    });
  });

  useSocketEvent('network_status', (data) => {
    if (data) setNetworkStatus(data);
  });

  useSocketEvent('security_event', (event) => {
    if (event) {
      setAlerts((prev) => [event, ...prev.slice(0, 49)]);
    }
  });

  const isCaptureRunning = trafficMetrics?.status === 'running';
  const isPermissionDenied = trafficMetrics?.status === 'permission_denied';

  // Filtered ARP mappings
  const filteredArp = arpMappings.filter((m) => {
    if (!arpSearch.trim()) return true;
    const term = arpSearch.toLowerCase();
    return (
      (m.ip || '').toLowerCase().includes(term) ||
      (m.mac || '').toLowerCase().includes(term) ||
      (m.vendor || '').toLowerCase().includes(term)
    );
  });

  return (
    <div className="network-page">
      <PageHeader
        title="Network Traffic & Threat Monitoring"
        subtitle="Live kernel-level raw frame ingestion, ARP poisoning inspection, and ICMP sweep tracking"
        actions={
          <button className="btn btn-secondary" onClick={loadNetworkData} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            Refresh
          </button>
        }
      />

      {error && <ErrorState error={error} onRetry={loadNetworkData} />}

      {/* Network KPI Cards */}
      <div className="metrics-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px', marginBottom: '20px' }}>
        <MetricCard
          title="Capture Interface"
          value={trafficMetrics?.interface || 'eth0'}
          subtext={`Socket State: ${trafficMetrics?.status?.toUpperCase() || 'UNKNOWN'}`}
          icon={Radio}
          badge={isCaptureRunning ? 'RUNNING' : isPermissionDenied ? 'PERM DENIED' : 'STOPPED'}
          badgeClass={isCaptureRunning ? 'badge-success' : isPermissionDenied ? 'badge-warning' : 'badge-danger'}
        />
        <MetricCard
          title="Packet Rate"
          value={`${formatNumber(trafficMetrics?.current_pps || 0, 0)} pps`}
          subtext={`Total Packets: ${formatNumber(trafficMetrics?.total_packets || 0)}`}
          icon={Activity}
        />
        <MetricCard
          title="Bandwidth Throughput"
          value={formatRate(trafficMetrics?.current_bps || 0, 'bps')}
          subtext={`Total Transferred: ${formatBytes(trafficMetrics?.total_bytes)}`}
          icon={Wifi}
        />
        <MetricCard
          title="Tracked ARP Mappings"
          value={formatNumber(arpMappings.length, 0)}
          subtext={`Conflicts detected: ${networkStatus?.arp?.conflicts_detected || 0}`}
          icon={Layers}
          badge={networkStatus?.arp?.conflicts_detected > 0 ? 'CONFLICT' : 'HEALTHY'}
          badgeClass={networkStatus?.arp?.conflicts_detected > 0 ? 'badge-critical' : 'badge-success'}
        />
      </div>

      {/* Traffic Trend Charts Grid */}
      <div className="dashboard-grid">
        <DashboardCard title="Live Packet Rate Trend (Packets/Sec)" icon={Activity}>
          {trafficHistory.length > 0 ? (
            <div style={{ height: '220px', width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficHistory}>
                  <defs>
                    <linearGradient id="netPpsGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} width={40} />
                  <Tooltip contentStyle={{ backgroundColor: '#131b2e', borderColor: '#1e293b' }} />
                  <Area type="monotone" dataKey="pps" stroke="#06b6d4" fillOpacity={1} fill="url(#netPpsGrad)" name="Packets/sec" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <LoadingState message="Collecting packet traffic samples..." />
          )}
        </DashboardCard>

        <DashboardCard title="Live Bandwidth Trend (Bytes/Sec)" icon={Wifi}>
          {trafficHistory.length > 0 ? (
            <div style={{ height: '220px', width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficHistory}>
                  <defs>
                    <linearGradient id="netBpsGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} width={50} tickFormatter={(val) => formatRate(val, 'bps')} />
                  <Tooltip contentStyle={{ backgroundColor: '#131b2e', borderColor: '#1e293b' }} formatter={(val) => [formatRate(val, 'bps'), 'Bandwidth']} />
                  <Area type="monotone" dataKey="bps" stroke="#3b82f6" fillOpacity={1} fill="url(#netBpsGrad)" name="Bandwidth" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <LoadingState message="Collecting bandwidth samples..." />
          )}
        </DashboardCard>
      </div>

      {/* Advanced Network Threats: ARP & ICMP Sweep */}
      <div className="dashboard-grid" style={{ marginTop: '20px' }}>
        <DashboardCard title="ARP Spoofing & Cache Poisoning Defense" icon={Layers}>
          <div className="status-detail-list">
            <div className="detail-item">
              <span className="detail-label">ARP Tracking State:</span>
              <span className={`badge ${networkStatus?.arp?.enabled !== false ? 'badge-success' : 'badge-danger'}`}>
                {networkStatus?.arp?.enabled !== false ? 'ACTIVE' : 'DISABLED'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Tracked IP-MAC Pairs:</span>
              <span className="detail-value">{formatNumber(networkStatus?.arp?.tracked_ips_count || arpMappings.length)}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Spoofing / Poisoning Alerts:</span>
              <span className={`badge ${(networkStatus?.arp?.spoof_alerts_count || 0) > 0 ? 'badge-critical' : 'badge-success'}`}>
                {networkStatus?.arp?.spoof_alerts_count || 0}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-label">IP Conflict Detections:</span>
              <span className={`badge ${(networkStatus?.arp?.conflicts_detected || 0) > 0 ? 'badge-warning' : 'badge-info'}`}>
                {networkStatus?.arp?.conflicts_detected || 0}
              </span>
            </div>
          </div>
        </DashboardCard>

        <DashboardCard title="ICMP Sweep & Reconnaissance Detector" icon={Radio}>
          <div className="status-detail-list">
            <div className="detail-item">
              <span className="detail-label">Detector Status:</span>
              <span className="badge badge-success">ACTIVE</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Sweep Threshold:</span>
              <span className="detail-value">{networkStatus?.icmp_sweep?.threshold || 10} targets / {networkStatus?.icmp_sweep?.window_sec || 10}s</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Active Tracked Sources:</span>
              <span className="detail-value">{formatNumber(networkStatus?.icmp_sweep?.tracked_sources || 0)}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Alert Cooldown Window:</span>
              <span className="detail-value">{networkStatus?.icmp_sweep?.cooldown_sec || 60} seconds</span>
            </div>
          </div>
        </DashboardCard>
      </div>

      {/* Tracked ARP Table */}
      <div style={{ marginTop: '20px' }}>
        <DashboardCard title={`Tracked ARP IP-to-MAC Mappings (${filteredArp.length})`} icon={Layers}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <div className="search-box" style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'var(--bg-dark)', padding: '6px 10px', borderRadius: '4px', border: '1px solid var(--border-color)', maxWidth: '280px' }}>
              <Search size={14} style={{ color: 'var(--text-muted)' }} />
              <input
                type="text"
                placeholder="Search IP, MAC, vendor..."
                value={arpSearch}
                onChange={(e) => setArpSearch(e.target.value)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-primary)', fontSize: '0.8rem', outline: 'none' }}
              />
            </div>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Showing {filteredArp.length} of {arpMappings.length} mappings
            </span>
          </div>

          {filteredArp.length > 0 ? (
            <div className="incident-table-wrapper" style={{ maxHeight: '280px', overflowY: 'auto' }}>
              <table className="incident-table" style={{ fontSize: '0.8rem' }}>
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Hardware MAC</th>
                    <th>Vendor / State</th>
                    <th>Type</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredArp.map((item, idx) => (
                    <tr key={idx}>
                      <td>
                        <code style={{ color: 'var(--accent-cyan)' }}>{item.ip}</code>
                      </td>
                      <td>
                        <code style={{ color: 'var(--text-secondary)' }}>{item.mac}</code>
                      </td>
                      <td>{item.vendor || item.state || 'Local Interface'}</td>
                      <td>
                        <span className={`badge ${item.is_static ? 'badge-info' : 'badge-secondary'}`}>
                          {item.is_static ? 'STATIC' : 'DYNAMIC'}
                        </span>
                      </td>
                      <td>{formatAlertTime(item.last_seen || item.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              title="No ARP Mappings"
              message={arpSearch ? 'No mappings match your search query.' : 'Awaiting ARP frame ingestion.'}
              icon={Layers}
            />
          )}
        </DashboardCard>
      </div>

      {/* Live Network Alerts Stream */}
      <div style={{ marginTop: '20px' }}>
        <DashboardCard title={`Recent Network Alerts (${alerts.length})`} icon={AlertTriangle}>
          {alerts.length > 0 ? (
            <div className="alerts-list" style={{ maxHeight: '260px', overflowY: 'auto' }}>
              {alerts.slice(0, 20).map((a, idx) => (
                <div key={idx} className="alert-item" style={{ padding: '8px 12px', marginBottom: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <SeverityBadge severity={a.severity} />
                      <strong style={{ fontSize: '0.84rem', color: 'var(--text-primary)' }}>
                        {a.detection_type}
                      </strong>
                    </div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {formatAlertTime(a.timestamp)}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                    Source: <code style={{ color: 'var(--accent-cyan)' }}>{a.source_ip}</code>
                    {a.target_ip && (
                      <> &rarr; Target: <code style={{ color: '#cbd5e1' }}>{a.target_ip}</code></>
                    )}
                    {a.target_port && <> (Port: {a.target_port})</>}
                  </div>
                  {a.description && (
                    <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                      {a.description}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              title="No Active Alerts"
              message="No intrusion detection signatures triggered in recent network traffic."
            />
          )}
        </DashboardCard>
      </div>
    </div>
  );
}

export default Network;
