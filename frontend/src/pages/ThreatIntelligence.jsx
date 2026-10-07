import React, { useState, useEffect, useCallback } from 'react';
import {
  Globe,
  Search,
  RotateCcw,
  CheckCircle2,
  AlertCircle,
  Shield,
  Layers,
  ExternalLink,
  Cpu,
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
  fetchThreatIntelStatus,
  fetchThreatIntelIP,
  requestThreatIntelLookup,
} from '../services/api';
import {
  formatNumber,
  formatPercent,
  formatConfidence,
  getReputationBadgeClass,
} from '../utils/formatters';

// Helper to check if an IPv4 address is private or loopback
function isPrivateOrLoopbackIP(ip) {
  if (!ip) return false;
  const trimmed = ip.trim();
  if (trimmed === 'localhost' || trimmed.startsWith('127.')) return true;
  if (trimmed.startsWith('10.')) return true;
  if (trimmed.startsWith('192.168.')) return true;
  if (trimmed === '::1' || trimmed === '0.0.0.0') return true;
  // 172.16.0.0 - 172.31.255.255
  const match = trimmed.match(/^172\.(\d{1,3})\./);
  if (match) {
    const secondOctet = parseInt(match[1], 10);
    if (secondOctet >= 16 && secondOctet <= 31) return true;
  }
  return false;
}

export default function ThreatIntelligence() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Search / Lookup state
  const [queryIP, setQueryIP] = useState('');
  const [lookupLoading, setLookupLoading] = useState(false);
  const [lookupResult, setLookupResult] = useState(null);
  const [lookupMessage, setLookupMessage] = useState(null);

  const loadData = useCallback(async () => {
    try {
      setError(null);
      const res = await fetchThreatIntelStatus();
      setStatus(res);
    } catch (err) {
      setError(err.message || 'Failed to load Threat Intelligence status');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [loadData]);

  // Real-time socket updates
  useSocketEvent('threat_intel_status', (data) => {
    if (data) setStatus(data);
  });

  useSocketEvent('threat_intel_update', (data) => {
    if (data?.ip && lookupResult?.intelligence?.ip === data.ip) {
      setLookupResult(data);
    }
  });

  const handleLookup = async () => {
    const ip = queryIP.trim();
    if (!ip) return;

    if (isPrivateOrLoopbackIP(ip)) {
      setLookupMessage({
        type: 'warning',
        text: `IP ${ip} is a private RFC1918 or loopback address. Threat intelligence queries only apply to public routable IP addresses.`,
      });
      setLookupResult(null);
      return;
    }

    setLookupLoading(true);
    setLookupMessage(null);
    setLookupResult(null);

    try {
      // First check if cached
      const cached = await fetchThreatIntelIP(ip);
      if (cached && cached.available && cached.intelligence) {
        setLookupResult(cached);
        setLookupMessage({
          type: 'success',
          text: `Found cached reputation record for ${ip} (Confidence: ${formatConfidence(cached.intelligence.confidence)}).`,
        });
        setLookupLoading(false);
        return;
      }

      // If not cached or explicitly requesting lookup
      const lookupReq = await requestThreatIntelLookup(ip);
      if (lookupReq?.queued || lookupReq?.success) {
        setLookupMessage({
          type: 'info',
          text: `Indicator lookup queued for ${ip}. Checking providers...`,
        });
        // Short delay to allow async worker processing
        setTimeout(async () => {
          const fresh = await fetchThreatIntelIP(ip);
          if (fresh && fresh.available) {
            setLookupResult(fresh);
            setLookupMessage(null);
          } else {
            setLookupMessage({
              type: 'info',
              text: `Lookup requested for ${ip}. Record will appear once upstream providers respond.`,
            });
          }
          setLookupLoading(false);
        }, 1500);
      } else {
        setLookupMessage({
          type: 'error',
          text: lookupReq?.message || lookupReq?.error || `No reputation intelligence available for ${ip}.`,
        });
        setLookupLoading(false);
      }
    } catch (err) {
      setLookupMessage({ type: 'error', text: err.message || 'Lookup request failed.' });
      setLookupLoading(false);
    }
  };

  if (loading && !status) {
    return <LoadingState message="Loading Threat Intelligence subsystem..." />;
  }

  if (error && !status) {
    return <ErrorState message={error} onRetry={loadData} />;
  }

  const isEnabled = status?.enabled ?? false;
  const configuredProviders = status?.configured_providers || [];
  const availableProviders = status?.available_providers || [];

  return (
    <div className="page-container">
      <PageHeader
        title="Threat Intelligence & Reputation"
        subtitle="External indicator reputation correlation, asynchronous provider lookups, and multi-source consensus"
        actions={
          <button className="btn-refresh" onClick={loadData} title="Refresh TI Status">
            <RotateCcw size={14} /> Refresh
          </button>
        }
      />

      {/* KPI Cards */}
      <div className="metric-cards-grid">
        <MetricCard
          title="Engine Status"
          value={isEnabled ? 'ACTIVE' : 'STANDBY'}
          subtext={isEnabled ? 'Asynchronous enrichment online' : 'Offline / Local detection only'}
          icon={Globe}
          badge={<StatusBadge status={isEnabled ? 'HEALTHY' : 'DISABLED'} text={isEnabled ? 'ENRICHING' : 'DISABLED'} />}
        />
        <MetricCard
          title="Providers Ready"
          value={`${availableProviders.length} / ${configuredProviders.length}`}
          subtext={configuredProviders.join(', ') || 'No external APIs configured'}
          icon={CheckCircle2}
          badge={<span className="badge badge-info">{configuredProviders.length} CONFIGURED</span>}
        />
        <MetricCard
          title="Reputation Cache"
          value={formatNumber(status?.cache_entries ?? 0)}
          subtext={`${status?.fresh_cache_entries ?? 0} fresh cached indicators`}
          icon={Layers}
          badge={<span className="badge badge-success">ACTIVE CACHE</span>}
        />
        <MetricCard
          title="Lookup Queries"
          value={formatNumber((status?.successful_lookups ?? 0) + (status?.failed_lookups ?? 0))}
          subtext={`${status?.successful_lookups ?? 0} resolved, ${status?.failed_lookups ?? 0} errors`}
          icon={Search}
          badge={<span className="badge badge-neutral">QUEUE: {status?.queue_size ?? 0}</span>}
        />
      </div>

      {/* Threat Intelligence Architecture & Reputation Legend */}
      <div style={{ marginTop: '1rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem' }}>
        <DashboardCard
          title="Threat Intelligence Subsystem Configuration"
          subtitle="External provider enrichment pipeline and query queue status"
          icon={Globe}
        >
          <div className="ti-container">
            <div className="ti-meta-banner">
              <div>
                <span className="ti-banner-label">Subsystem Status: </span>
                <span className={`badge ${isEnabled ? 'badge-status-open' : 'badge-low'}`} style={{ padding: '0.15rem 0.45rem', fontSize: '0.65rem' }}>
                  {isEnabled ? 'ACTIVE (ENRICHING)' : 'DISABLED (STANDBY)'}
                </span>
              </div>
              <div style={{ marginTop: '0.4rem' }}>
                <span className="ti-banner-label">Configured Providers: </span>
                <span style={{ color: '#cbd5e1', fontSize: '0.75rem' }}>
                  {configuredProviders.length > 0
                    ? configuredProviders.join(', ')
                    : 'None (Local / offline mode. Set ABUSEIPDB_API_KEY or VIRUSTOTAL_API_KEY in .env to enable)'}
                </span>
              </div>
            </div>

            <div className="ti-stats-grid">
              <div className="ti-stat-card">
                <span className="ti-stat-label">Providers Ready</span>
                <span className="ti-stat-val" style={{ color: availableProviders.length > 0 ? '#10b981' : '#94a3b8' }}>
                  {availableProviders.length} / {configuredProviders.length}
                </span>
              </div>
              <div className="ti-stat-card">
                <span className="ti-stat-label">Queue Load</span>
                <span className="ti-stat-val" style={{ color: (status?.queue_size || 0) > 100 ? '#f59e0b' : '#38bdf8' }}>
                  {status?.queue_size || 0} / {status?.queue_capacity || 500}
                </span>
              </div>
              <div className="ti-stat-card">
                <span className="ti-stat-label">Cache Entries</span>
                <span className="ti-stat-val" style={{ color: '#a855f7' }}>
                  {status?.cache_entries || 0} ({status?.fresh_cache_entries || 0} fresh)
                </span>
              </div>
              <div className="ti-stat-card">
                <span className="ti-stat-label">Lookups</span>
                <span className="ti-stat-val" style={{ color: '#38bdf8' }}>
                  {status?.successful_lookups || 0} ok / {status?.failed_lookups || 0} err
                </span>
              </div>
            </div>
          </div>
        </DashboardCard>

        <DashboardCard
          title="Consensus & Reputation Taxonomy"
          subtitle="Semantic classification rules applied to external indicator telemetry"
          icon={Shield}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', fontSize: '0.75rem', color: '#cbd5e1' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.4rem 0.6rem', background: 'rgba(15, 23, 42, 0.6)', borderRadius: '4px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span className="badge badge-low" style={{ minWidth: '70px', textAlign: 'center' }}>CLEAN</span>
                <span>Indicator verified benign across all queried providers</span>
              </div>
              <span style={{ color: '#10b981', fontWeight: 600 }}>0 Risk Adder</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.4rem 0.6rem', background: 'rgba(15, 23, 42, 0.6)', borderRadius: '4px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span className="badge badge-medium" style={{ minWidth: '70px', textAlign: 'center' }}>SUSPICIOUS</span>
                <span>Low-to-moderate report volume or suspicious ASN classification</span>
              </div>
              <span style={{ color: '#f59e0b', fontWeight: 600 }}>+15 Risk Adder</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.4rem 0.6rem', background: 'rgba(15, 23, 42, 0.6)', borderRadius: '4px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span className="badge badge-critical" style={{ minWidth: '70px', textAlign: 'center' }}>MALICIOUS</span>
                <span>Known C2, brute-force source, or malware distribution node</span>
              </div>
              <span style={{ color: '#ef4444', fontWeight: 600 }}>+30 Risk Adder</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.4rem 0.6rem', background: 'rgba(15, 23, 42, 0.6)', borderRadius: '4px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span className="badge badge-high" style={{ minWidth: '70px', textAlign: 'center' }}>CONFLICT</span>
                <span>Discrepancy between providers; conservative evaluation applied</span>
              </div>
              <span style={{ color: '#f97316', fontWeight: 600 }}>Partial Adder</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.4rem 0.6rem', background: 'rgba(15, 23, 42, 0.6)', borderRadius: '4px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span className="badge badge-neutral" style={{ minWidth: '70px', textAlign: 'center' }}>UNKNOWN</span>
                <span>No provider data or API keys unconfigured (UNKNOWN != CLEAN)</span>
              </div>
              <span style={{ color: '#94a3b8', fontWeight: 600 }}>Neutral</span>
            </div>
          </div>
        </DashboardCard>
      </div>

      {/* Interactive Public IP Inspector Tool */}
      <div style={{ marginTop: '1rem' }}>
        <DashboardCard title="Interactive Public Indicator Reputation Inspector" icon={Search}>
          <div className="ti-inspector-box" style={{ margin: '0.5rem 0' }}>
            <div className="ti-inspector-header">
              <span style={{ fontWeight: 600, fontSize: '0.85rem', color: '#f1f5f9', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <Search size={15} /> Search External Reputation
              </span>
              <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Public IPv4 / IPv6 addresses only</span>
            </div>

            <div className="ti-search-bar">
              <input
                type="text"
                className="ti-search-input"
                placeholder="Enter external public IP (e.g. 198.51.100.25)..."
                value={queryIP}
                onChange={(e) => setQueryIP(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
              />
              <button
                type="button"
                className="ti-btn-primary"
                onClick={handleLookup}
                disabled={lookupLoading || !queryIP.trim()}
              >
                {lookupLoading ? 'Checking...' : 'Check Reputation'}
              </button>
            </div>

            {lookupMessage && (
              <div className={`ti-msg-banner ${lookupMessage.type}`} style={{ margin: '0.75rem 0' }}>
                {lookupMessage.text}
              </div>
            )}

            {lookupResult?.intelligence && (
              <div className="ti-result-card" style={{ marginTop: '1rem' }}>
                <div className="ti-result-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '0.95rem', color: '#f8fafc' }}>
                      {lookupResult.intelligence.ip}
                    </span>
                    <span className={`badge ${getReputationBadgeClass(lookupResult.intelligence.reputation)}`}>
                      {lookupResult.intelligence.reputation}
                    </span>
                    <span className="badge badge-consensus" style={{ fontSize: '0.65rem' }}>
                      {lookupResult.intelligence.consensus}
                    </span>
                    {lookupResult.intelligence.stale && (
                      <span className="badge badge-stale" style={{ fontSize: '0.65rem', backgroundColor: '#475569', color: '#cbd5e1' }}>
                        STALE
                      </span>
                    )}
                  </div>
                  <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                    Confidence: {formatConfidence(lookupResult.intelligence.confidence)}
                  </span>
                </div>

                <div className="ti-details-grid">
                  <div className="ti-detail-item">
                    <span className="ti-detail-label">Abuse Score</span>
                    <span className="ti-detail-val">
                      {lookupResult.intelligence.abuse_score !== null && lookupResult.intelligence.abuse_score !== undefined
                        ? `${lookupResult.intelligence.abuse_score}/100`
                        : 'N/A'}
                    </span>
                  </div>
                  <div className="ti-detail-item">
                    <span className="ti-detail-label">Report Count</span>
                    <span className="ti-detail-val">{lookupResult.intelligence.report_count ?? 0}</span>
                  </div>
                  <div className="ti-detail-item">
                    <span className="ti-detail-label">Country</span>
                    <span className="ti-detail-val">{lookupResult.intelligence.country || 'Unknown'}</span>
                  </div>
                  <div className="ti-detail-item">
                    <span className="ti-detail-label">ASN / Owner</span>
                    <span className="ti-detail-val">
                      {lookupResult.intelligence.asn ? `AS${lookupResult.intelligence.asn} ` : ''}
                      {lookupResult.intelligence.as_owner || 'N/A'}
                    </span>
                  </div>
                </div>

                {/* Provider Breakdown Cards */}
                {Object.keys(lookupResult.intelligence.provider_results || {}).length > 0 && (
                  <div className="ti-provider-results-list" style={{ marginTop: '0.75rem' }}>
                    {Object.entries(lookupResult.intelligence.provider_results).map(([pName, pRes]) => (
                      <div key={pName} className="ti-provider-card">
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ fontWeight: 600, color: '#f1f5f9', fontSize: '0.75rem' }}>{pName}</span>
                          <span className={`badge ${getReputationBadgeClass(pRes.reputation)}`} style={{ fontSize: '0.6rem', padding: '0.1rem 0.35rem' }}>
                            {pRes.reputation}
                          </span>
                        </div>
                        <div style={{ fontSize: '0.7rem', color: '#94a3b8', display: 'flex', gap: '0.75rem', marginTop: '0.25rem' }}>
                          {pRes.abuse_confidence !== undefined && (
                            <span>Abuse Conf: {pRes.abuse_confidence}%</span>
                          )}
                          {pRes.report_count !== undefined && (
                            <span>Reports: {pRes.report_count}</span>
                          )}
                          {pRes.malicious_score !== undefined && pName === 'VirusTotal' && (
                            <span>Detections: {pRes.malicious_score}</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Contextual Disclaimer */}
                <div className="ti-disclaimer" style={{ marginTop: '0.75rem' }}>
                  <AlertCircle size={13} style={{ flexShrink: 0, marginTop: '1px' }} />
                  <span>
                    External reputation sources classify this IP as <strong>{lookupResult.intelligence.reputation.toLowerCase()}</strong>.
                    Threat intelligence is contextual evidence and does not constitute absolute proof of compromise.
                  </span>
                </div>
              </div>
            )}
          </div>
        </DashboardCard>
      </div>
    </div>
  );
}
