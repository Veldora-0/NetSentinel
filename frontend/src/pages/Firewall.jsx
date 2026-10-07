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
  Info,
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
import { formatNumber, formatFullTime, formatAlertTime } from '../utils/formatters';

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
        setFeedback({ type: 'success', text: `Block action recorded for IP ${targetIP.trim()}` });
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
    setActionLoading(true);
    setFeedback(null);
    try {
      const res = await manualUnblockIP(ip);
      if (res?.status === 'success' || res?.success) {
        setFeedback({ type: 'success', text: `Removed mitigation rule for ${ip}` });
        await loadData();
      } else {
        setFeedback({ type: 'error', text: res?.message || `Failed to unblock ${ip}` });
      }
    } catch (err) {
      setFeedback({ type: 'error', text: err.message || `Error unblocking ${ip}` });
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
        subtitle="Active Linux netfilter kernel integration, automated risk mitigation, and manual host quarantine controls"
        actions={
          <button className="btn-refresh" onClick={loadData} title="Refresh Firewall State">
            <RotateCcw size={14} /> Refresh
          </button>
        }
      />

      {/* Prominent Safety Constraint Notice */}
      {!isEnabled ? (
        <div className="safety-banner info">
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
            <Shield size={20} style={{ color: 'var(--accent-cyan)', flexShrink: 0, marginTop: '2px' }} />
            <div>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '2px' }}>
                Firewall Mitigation Inactive (Safe Evaluation Mode)
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
                Netfilter rule injection is currently disabled (`NETSENTINEL_FIREWALL_ENABLED=false`). In this demonstration posture, no network packets are dropped at the Linux kernel level. Automatic blocking is also disabled (`NETSENTINEL_AUTO_BLOCK=false`). Any quarantine actions executed here operate in simulated dry-run tracking mode without mutating kernel chains.
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="safety-banner warning">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertTriangle size={18} style={{ color: '#f59e0b', flexShrink: 0 }} />
            <span>
              <strong>Kernel Netfilter Active:</strong> iptables drop rules are actively inserted into the `{firewallStatus?.chain || 'NETSENTINEL'}` chain.
            </span>
          </div>
        </div>
      )}

      {/* Metric Cards Row */}
      <div className="metric-cards-grid">
        <MetricCard
          title="Active Blocked IPs"
          value={formatNumber(blockedIPs.length)}
          subtext="Currently tracked quarantine rules"
          icon={Lock}
          badge={
            blockedIPs.length > 0 ? (
              <span className="badge badge-critical">{blockedIPs.length} BLOCKED</span>
            ) : (
              <span className="badge badge-neutral">ZERO BLOCKS</span>
            )
          }
        />
        <MetricCard
          title="iptables Engine"
          value={isEnabled ? 'ENABLED' : 'DISABLED'}
          subtext={`Chain: ${firewallStatus?.chain || 'NETSENTINEL'}`}
          icon={Shield}
          badge={<StatusBadge status={isEnabled ? 'HEALTHY' : 'DISABLED'} text={isEnabled ? 'ONLINE' : 'STANDBY'} />}
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
          value={isDryRun ? 'DRY-RUN' : isEnabled ? 'LIVE KERNEL' : 'DISABLED'}
          subtext={isDryRun ? 'Simulated rules without kernel drops' : isEnabled ? 'Active Linux netfilter' : 'Demonstration safe mode'}
          icon={CheckCircle2}
          badge={<span className={`badge ${isDryRun || !isEnabled ? 'badge-warning' : 'badge-success'}`}>{isDryRun || !isEnabled ? 'SAFE MODE' : 'LIVE'}</span>}
        />
      </div>

      {feedback && (
        <div className={`safety-banner ${feedback.type === 'success' ? 'info' : 'danger'}`}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {feedback.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
            <span>{feedback.text}</span>
          </div>
          <button onClick={() => setFeedback(null)} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer' }}>
            ×
          </button>
        </div>
      )}

      {/* Manual IP Quarantine Form */}
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
                disabled={actionLoading}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.25rem' }}>
                Quarantine Reason
              </label>
              <input
                type="text"
                className="ti-search-input"
                style={{ width: '100%' }}
                placeholder="Reason for blocking..."
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                disabled={actionLoading}
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
                disabled={actionLoading}
              >
                <option value="60">1 Minute (Test)</option>
                <option value="300">5 Minutes (Default)</option>
                <option value="900">15 Minutes</option>
                <option value="3600">1 Hour</option>
                <option value="86400">24 Hours</option>
                <option value="0">Indefinite</option>
              </select>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.25rem' }}>
            <button
              type="submit"
              className="ti-btn-primary"
              disabled={actionLoading || !targetIP.trim()}
              style={{ backgroundColor: '#ef4444', borderColor: '#ef4444' }}
            >
              <Lock size={14} style={{ marginRight: '0.35rem' }} />
              {actionLoading ? 'Applying...' : 'Quarantine / Block IP'}
            </button>
          </div>
        </form>
      </DashboardCard>

      {/* Active Blocked IPs Table Card */}
      <DashboardCard title={`Active Mitigated Hosts (${blockedIPs.length})`} icon={Lock}>
        {blockedIPs.length === 0 ? (
          <EmptyState
            title="Zero Active Blocks"
            message="No hosts are currently blocked. Normal traffic flows unimpeded."
            icon={Shield}
          />
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="soc-table">
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
                {blockedIPs.map((blk) => (
                  <tr key={blk.ip}>
                    <td>
                      <code style={{ color: '#f87171', fontWeight: 600, fontSize: '0.85rem' }}>
                        {blk.ip}
                      </code>
                    </td>
                    <td style={{ color: '#f8fafc', fontSize: '0.8rem' }}>
                      {blk.reason || 'Automated high risk threshold mitigation'}
                    </td>
                    <td style={{ color: '#94a3b8', fontSize: '0.74rem' }}>
                      {blk.blocked_at ? formatFullTime(blk.blocked_at) : 'Active'}
                    </td>
                    <td style={{ color: '#94a3b8', fontSize: '0.74rem' }}>
                      {blk.expires_at ? (
                        <span>Expires {formatAlertTime(blk.expires_at)}</span>
                      ) : (
                        <span style={{ color: '#fca5a5', fontWeight: 600 }}>Indefinite</span>
                      )}
                    </td>
                    <td>
                      <button
                        className="btn-unblock"
                        disabled={actionLoading}
                        onClick={() => handleUnblock(blk.ip)}
                        title="Remove mitigation rule"
                      >
                        <Unlock size={12} style={{ marginRight: '0.25rem' }} />
                        Unblock
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </DashboardCard>
    </div>
  );
}
