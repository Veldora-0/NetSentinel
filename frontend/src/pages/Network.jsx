import React, { useState, useEffect, useCallback } from 'react';
import {
  Activity,
  Radio,
  AlertTriangle,
  RotateCcw,
  Search,
  Wifi,
  Layers,
  ArrowRight,
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
  safeNumber,
  PROTOCOL_COLORS,
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

  const loadNetworkData = useCallback(async () => {
    setError(null);
    try {
      const [netStatusRes, arpRes, alertsRes] = await Promise.allSettled([
        fetchNetworkStatus(),
        fetchARPMappings(100),
        fetchSecurityAlerts(50),
      ]);

      let captureData = null;
      if (netStatusRes.status === 'fulfilled' && netStatusRes.value) {
        const net = netStatusRes.value.network || netStatusRes.value;
        if (netStatusRes.value.network) setNetworkStatus(netStatusRes.value.network);
        captureData = net?.capture || netStatusRes.value.capture || null;
      }

      // Fallback to fetchTrafficMetrics only if network status did not provide capture payload
      if (!captureData) {
        try {
          captureData = await fetchTrafficMetrics();
        } catch {
          // ignore fallback error
        }
      }

      if (captureData) {
        setTrafficMetrics(captureData);
        setTrafficHistory((prev) => {
          if (prev.length === 0) {
            const nowStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            return [{
              time: nowStr,
              pps: safeNumber(captureData.current_pps ?? captureData.packets_per_sec, 0),
              bps: safeNumber(captureData.current_bps ?? captureData.bytes_per_sec, 0),
            }];
          }
          return prev;
        });
      }

      if (arpRes.status === 'fulfilled' && arpRes.value?.mappings) setArpMappings(arpRes.value.mappings);
      if (alertsRes.status === 'fulfilled' && Array.isArray(alertsRes.value)) setAlerts(alertsRes.value);
    } catch (err) {
      setError(err.message || 'Failed to load network traffic data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadNetworkData();
    const interval = setInterval(loadNetworkData, 15000);
    return () => clearInterval(interval);
  }, [loadNetworkData]);

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
      const pps = safeNumber(data.current_pps ?? data.packets_per_sec, 0);
      const bps = safeNumber(data.current_bps ?? data.bytes_per_sec, 0);
      const updated = [...prev, { time: nowStr, pps, bps }];
      return updated.length > 30 ? updated.slice(-30) : updated;
    });
  });

  useSocketEvent('network_status', (data) => {
    if (data) {
      setNetworkStatus(data);
      if (data.capture) setTrafficMetrics(data.capture);
    }
  });

  useSocketEvent('security_event', (event) => {
    if (event) {
      setAlerts((prev) => [event, ...prev.slice(0, 49)]);
    }
  });

  const activeInterface =
    trafficMetrics?.actual_interface ||
    trafficMetrics?.interface ||
    trafficMetrics?.configured_interface ||
    networkStatus?.capture?.actual_interface ||
    networkStatus?.capture?.interface ||
    networkStatus?.capture?.configured_interface ||
    'Unavailable';

  const currentStatus = trafficMetrics?.status || networkStatus?.capture?.status || 'stopped';
  const isCaptureRunning = currentStatus === 'running';
  const isPermissionDenied = currentStatus === 'permission_denied';
  const isCaptureError = currentStatus === 'error';

  const socketState =
    trafficMetrics?.socket_state ||
    networkStatus?.capture?.socket_state ||
    (isCaptureRunning ? 'OPEN' : isPermissionDenied ? 'PERMISSION_DENIED' : isCaptureError ? 'ERROR' : 'CLOSED');

  const captureErrorMsg =
    trafficMetrics?.error ||
    trafficMetrics?.last_error ||
    networkStatus?.capture?.error ||
    networkStatus?.capture?.last_error ||
    null;

  // Real protocol distribution breakdown
  const protocolData = [
    { name: 'TCP', count: safeNumber(trafficMetrics?.tcp_packets, 0), color: PROTOCOL_COLORS.TCP },
    { name: 'UDP', count: safeNumber(trafficMetrics?.udp_packets, 0), color: PROTOCOL_COLORS.UDP },
    { name: 'ICMP', count: safeNumber(trafficMetrics?.icmp_packets, 0), color: PROTOCOL_COLORS.ICMP },
    { name: 'ARP', count: safeNumber(trafficMetrics?.arp_packets, 0), color: PROTOCOL_COLORS.ARP },
    { name: 'Other', count: safeNumber(trafficMetrics?.other_packets, 0), color: PROTOCOL_COLORS.OTHER },
  ];
  const totalProtocolPackets = protocolData.reduce((acc, p) => acc + p.count, 0);

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
    <div className="page-container">
      <PageHeader
        title="Network Traffic & Threat Monitoring"
        subtitle="Live kernel AF_PACKET frame ingestion, layer 2/3 protocol telemetry, and advanced ARP/ICMP detection"
        actions={
          <button className="btn-refresh" onClick={loadNetworkData} title="Refresh Network Telemetry">
            <RotateCcw size={14} /> Refresh
          </button>
        }
      />

      {error && <ErrorState message={error} onRetry={loadNetworkData} />}

      {captureErrorMsg && !isCaptureRunning && (
        <div className="alert-banner warning" style={{ marginBottom: '1.25rem', padding: '0.875rem 1rem', display: 'flex', alignItems: 'center', gap: '0.75rem', borderRadius: '6px', background: 'rgba(234, 179, 8, 0.1)', border: '1px solid rgba(234, 179, 8, 0.3)', color: '#eab308' }}>
          <AlertTriangle size={18} />
          <span><strong>Capture Subsystem:</strong> {captureErrorMsg}</span>
        </div>
      )}

      {/* Network KPI Cards */}
      <div className="metric-cards-grid">
        <MetricCard
          title="Capture Interface"
          value={activeInterface}
          subtext={`Socket State: ${socketState}`}
          icon={Radio}
          badge={
            <span className={`badge ${isCaptureRunning ? 'badge-success' : isPermissionDenied ? 'badge-warning' : isCaptureError ? 'badge-critical' : 'badge-danger'}`}>
              {isCaptureRunning ? 'RUNNING' : isPermissionDenied ? 'PERM DENIED' : isCaptureError ? 'ERROR' : 'STOPPED'}
            </span>
          }
        />
        <MetricCard
          title="Packet Ingestion Rate"
          value={`${formatNumber(trafficMetrics?.current_pps ?? trafficMetrics?.packets_per_sec ?? networkStatus?.capture?.current_pps ?? networkStatus?.capture?.packets_per_sec ?? 0, 0)} pps`}
          subtext={`Total Frames: ${formatNumber(trafficMetrics?.total_packets ?? trafficMetrics?.total_frames ?? networkStatus?.capture?.total_packets ?? 0)}`}
          icon={Activity}
        />
        <MetricCard
          title="Bandwidth Throughput"
          value={formatRate(trafficMetrics?.current_bps ?? trafficMetrics?.bytes_per_sec ?? 0, 'bps')}
          subtext={`Total Volume: ${formatBytes(trafficMetrics?.total_bytes)}`}
          icon={Wifi}
        />
        <MetricCard
          title="Tracked ARP Neighbors"
          value={formatNumber(arpMappings.length, 0)}
          subtext={`Conflicts: ${networkStatus?.arp?.conflicts_detected || 0} detected`}
          icon={Layers}
          badge={
            (networkStatus?.arp?.conflicts_detected || 0) > 0 ? (
              <span className="badge badge-critical">CONFLICT</span>
            ) : (
              <span className="badge badge-success">HEALTHY</span>
            )
          }
        />
      </div>

      {/* Traffic Trend & Protocol Breakdown Grid */}
      <div className="dashboard-grid">
        <DashboardCard title="Live Ingestion Rate (Packets / Second)" icon={Activity}>
          {trafficHistory.length > 0 ? (
            <div style={{ height: '220px', width: '100%', marginTop: '6px' }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficHistory} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="netPpsGrad" x1="0" y1="0" x2="0" y2="1">
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
                    fill="url(#netPpsGrad)"
                    name="Packets/sec"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <LoadingState message="Collecting packet traffic samples..." compact />
          )}
        </DashboardCard>

        <DashboardCard title="Captured Protocol Volume Distribution" icon={Wifi}>
          {totalProtocolPackets > 0 ? (
            <div style={{ height: '220px', width: '100%', marginTop: '6px' }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={protocolData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                  <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} width={45} tickFormatter={(v) => formatNumber(v)} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                    formatter={(val) => [`${formatNumber(val)} frames (${((val / totalProtocolPackets) * 100).toFixed(1)}%)`, 'Volume']}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {protocolData.map((entry, index) => (
                      <Cell key={`proto-cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState
              title="No Protocol Data"
              message="No packet frames have been captured yet to compute protocol distribution."
              icon={Wifi}
            />
          )}
        </DashboardCard>
      </div>

      {/* Advanced Network Threats: ARP & ICMP Sweep */}
      <div className="dashboard-grid">
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

      {/* Tracked ARP IP-to-MAC Table */}
      <DashboardCard
        title={`Tracked ARP Neighbor Mappings (${filteredArp.length})`}
        icon={Layers}
        headerRight={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'var(--bg-dark)', padding: '4px 8px', borderRadius: '4px', border: '1px solid var(--border-color)' }}>
              <Search size={13} color="#64748b" />
              <input
                type="text"
                placeholder="Search IP, MAC, vendor..."
                value={arpSearch}
                onChange={(e) => setArpSearch(e.target.value)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-primary)', fontSize: '0.75rem', outline: 'none', width: '150px' }}
              />
            </div>
            <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
              {filteredArp.length} of {arpMappings.length}
            </span>
          </div>
        }
      >
        {filteredArp.length > 0 ? (
          <div style={{ overflowX: 'auto', maxHeight: '250px' }}>
            <table className="soc-table">
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
                      <code style={{ color: '#94a3b8' }}>{item.mac}</code>
                    </td>
                    <td>{item.vendor || item.state || 'Interface Local'}</td>
                    <td>
                      <span className={`badge ${item.is_static ? 'badge-info' : 'badge-neutral'}`}>
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

      {/* Live Network Detections Stream */}
      <DashboardCard title={`Recent Network Detections (${alerts.length})`} icon={ShieldAlert}>
        {alerts.length > 0 ? (
          <div className="alerts-list" style={{ maxHeight: '240px', overflowY: 'auto' }}>
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
  );
}

export default Network;
