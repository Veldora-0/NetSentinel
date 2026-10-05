import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  Lock,
  Unlock,
  RotateCcw,
  AlertTriangle,
  CheckCircle2,
  Clock,
  PlusCircle,
} from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { MetricCard } from '../components/common/MetricCard';
import { StatusBadge } from '../components/common/StatusBadge';
import { DashboardCard } from '../components/DashboardCard';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { useSocketEvent } from '../hooks/useSocketEvent';
import {
  fetchFirewallStatus,
  fetchBlockedIPs,
  manualBlockIP,
  manualUnblockIP,
} from '../services/api';
import { formatNumber, formatFullTime } from '../utils/formatters';

export default function Firewall() {
  const [firewallStatus, setFirewallStatus] = useState(null);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Manual block form state
  const [targetIP, setTargetIP] = useState('');
  const [reason, setReason] = useState('Operator Manual Block');
  const [duration, setDuration] = useState('300');
  const [actionLoading, setActionLoading] = useState(false);
  const [feedback, setFeedback] = useState(null);

  const loadData = useCallback(async () => {
    try {
      setError(null);
      const [fStatus, bIPs] = await Promise.all([
        fetchFirewallStatus(),
        fetchBlockedIPs(),
      ]);
      setFirewallStatus(fStatus);
      setBlockedIPs(bIPs || []);
    } catch (err) {
      setError(err.message || 'Failed to load Firewall data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, [loadData]);

  // Socket.IO updates
  useSocketEvent('firewall_status', (data) => {
    if (data) setFirewallStatus(data);
  });

  useSocketEvent('blocked_ips', (data) => {
    if (Array.isArray(data)) setBlockedIPs(data);
    else loadData();
  });

  useSocketEvent('firewall_action', () => {
    loadData();
  });

  const handleManualBlock = async (e) => {
    e.preventDefault();
    if (!targetIP.trim()) return;

    setActionLoading(true);
    setFeedback(null);
    try {
      const durSeconds = parseInt(duration, 10) || 300;
      const res = await manualBlockIP(targetIP.trim(), reason.trim(), durSeconds);
      if (res?.status === 'success' || res?.success) {
        setFeedback({ type: 'success', text: `Successfully blocked IP ${targetIP.trim()}` });
        setTargetIP('');
        await loadData();
      } else {
        setFeedback({ type: 'error', text: res?.message || 'Failed to block IP' });
      }
    } catch (err) {
      setFeedback({ type: 'error', text: err.message || 'Error executing block action' });
    } finally {
      setActionLoading(false);
    }
  };

  const handleUnblock = async (ip) => {
    if (!window.confirm(`Unblock IP ${ip}? This will immediately remove the iptables rule.`)) {
      return;
    }
    setActionLoading(true);
    setFeedback(null);
    try {
      const res = await manualUnblockIP(ip);
      if (res?.status === 'success' || res?.success) {
        setFeedback({ type: 'success', text: `Successfully unblocked IP ${ip}` });
        await loadData();
      } else {
        setFeedback({ type: 'error', text: res?.message || 'Failed to unblock IP' });
      }
    } catch (err) {
      setFeedback({ type: 'error', text: err.message || 'Error executing unblock action' });
    } finally {
      setActionLoading(false);
    }
  };

  if (loading && !firewallStatus) {
    return <LoadingState message="Loading Firewall subsystem status..." />;
  }

  if (error && !firewallStatus) {
    return <ErrorState message={error} onRetry={loadData} />;
  }

  const isEnabled = firewallStatus?.enabled ?? false;
  const isAutoBlock = firewallStatus?.auto_block ?? false;
  const isDryRun = firewallStatus?.dry_run ?? false;

  return (
    <div className="page-container">
      <PageHeader
        title="Firewall Mitigation (iptables)"
        subtitle="Active kernel firewall integration, automated risk mitigation, and manual host isolation controls"
        actions={
          <button className="btn-refresh" onClick={loadData} title="Refresh Firewall State">
            <RotateCcw size={14} /> Refresh
          </button>
        }
      />

      {/* Metric Cards Row */}
      <div className="metric-cards-grid">
        <MetricCard
          title="Active Blocked IPs"
          value={formatNumber(blockedIPs.length)}
          subtext="Currently enforced drop rules"
          icon={Lock}
          badge={
            blockedIPs.length > 0 ? (
              <span className="badge badge-critical">{blockedIPs.length} BLOCKED</span>
            ) : (
              <span className="badge badge-neutral">NONE</span>
            )
          }
        />
        <MetricCard
          title="iptables Engine"
          value={isEnabled ? 'ENABLED' : 'DISABLED'}
          subtext={`Chain: ${firewallStatus?.chain || 'NETSENTINEL'}`}
          icon={Shield}
          badge={<StatusBadge status={isEnabled ? 'HEALTHY' : 'DISABLED'} text={isEnabled ? 'ONLINE' : 'OFFLINE'} />}
        />
        <MetricCard
          title="Automated Defense"
          value={isAutoBlock ? 'ACTIVE' : 'STANDBY'}
          subtext={isAutoBlock ? 'Auto-blocking high-risk attacks' : 'Manual mitigation only'}
          icon={AlertTriangle}
          badge={
            isAutoBlock ? (
              <span className="badge badge-critical">AUTO-BLOCK ON</span>
            ) : (
              <span className="badge badge-neutral">AUTO-BLOCK OFF</span>
            )
          }
        />
        <MetricCard
          title="Execution Mode"
          value={isDryRun ? 'DRY-RUN' : 'LIVE KERNEL'}
          subtext={isDryRun ? 'Simulated rules without kernel drops' : 'Active Linux netfilter filtering'}
          icon={CheckCircle2}
          badge={<span className={`badge ${isDryRun ? 'badge-warning' : 'badge-success'}`}>{isDryRun ? 'SIMULATED' : 'LIVE'}</span>}
        />
      </div>

      {feedback && (
        <div
          style={{
            margin: '1rem 0',
            padding: '0.75rem 1rem',
            borderRadius: '6px',
            fontSize: '0.85rem',
            background: feedback.type === 'success' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
            border: `1px solid ${feedback.type === 'success' ? '#10b981' : '#ef4444'}`,
            color: feedback.type === 'success' ? '#86efac' : '#fca5a5',
          }}
        >
          {feedback.text}
        </div>
      )}

      {/* Grid: Manual Block Form & Status */}
      <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr', gap: '1rem', marginTop: '1rem' }}>
        {/* Manual Block Card */}
        <DashboardCard title="Manual IP Quarantine Control" icon={PlusCircle}>
          <form onSubmit={handleManualBlock} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.25rem' }}>
                  Target IP Address
                </label>
                <input
                  type="text"
                  className="ti-search-input"
                  style={{ width: '100%' }}
                  placeholder="e.g. 198.51.100.12 or 10.0.0.99"
                  value={targetIP}
                  onChange={(e) => setTargetIP(e.target.value)}
                  required
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.25rem' }}>
                  Mitigation Reason
                </label>
                <input
                  type="text"
                  className="ti-search-input"
                  style={{ width: '100%' }}
                  placeholder="e.g. Malicious scanning observed"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.25rem' }}>
                  Duration
                </label>
                <select
                  className="history-filter-select"
                  style={{ width: '100%', height: '36px' }}
                  value={duration}
                  onChange={(e) => setDuration(e.target.value)}
                >
                  <option value="60">1 minute (Test)</option>
                  <option value="300">5 minutes (Default)</option>
                  <option value="1800">30 minutes</option>
                  <option value="3600">1 hour</option>
                  <option value="86400">24 hours</option>
                  <option value="0">Permanent (Until manual unblock)</option>
                </select>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
              <button
                type="submit"
                className="ti-btn-primary"
                disabled={actionLoading || !targetIP.trim()}
                style={{ backgroundColor: '#ef4444', borderColor: '#ef4444' }}
              >
                <Lock size={14} style={{ marginRight: '0.35rem' }} />
                {actionLoading ? 'Applying Rule...' : 'Quarantine / Block IP'}
              </button>
            </div>
          </form>
        </DashboardCard>

        {/* Active Blocked IPs Table Card */}
        <DashboardCard title={`Active Netfilter Blocks (${blockedIPs.length})`} icon={Lock}>
          <div className="history-table-container">
            <table className="history-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Reason / Trigger</th>
                  <th>Blocked At</th>
                  <th>Expiration</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {blockedIPs.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="history-empty-row">
                      No actively blocked IP addresses. All network traffic is allowed through standard chains.
                    </td>
                  </tr>
                ) : (
                  blockedIPs.map((blk) => (
                    <tr key={blk.ip}>
                      <td style={{ fontFamily: 'monospace', fontWeight: 600, color: '#f43f5e', fontSize: '0.85rem' }}>
                        {blk.ip}
                      </td>
                      <td style={{ color: '#f8fafc', fontSize: '0.8rem' }}>
                        {blk.reason || 'Automated high risk threshold mitigation'}
                      </td>
                      <td style={{ color: '#94a3b8', fontSize: '0.75rem' }}>
                        {blk.blocked_at ? formatFullTime(blk.blocked_at) : 'Active'}
                      </td>
                      <td style={{ color: '#94a3b8', fontSize: '0.75rem' }}>
                        {blk.expires_at ? (
                          <span>Expires {new Date(blk.expires_at * 1000).toLocaleTimeString()}</span>
                        ) : (
                          <span style={{ color: '#fca5a5', fontWeight: 600 }}>Permanent</span>
                        )}
                      </td>
                      <td>
                        <button
                          className="btn-unblock"
                          disabled={actionLoading}
                          onClick={() => handleUnblock(blk.ip)}
                          title="Unblock IP and remove iptables drop rule"
                        >
                          <Unlock size={12} style={{ marginRight: '0.25rem' }} />
                          Unblock
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </DashboardCard>
      </div>
    </div>
  );
}
