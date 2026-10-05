import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Clock,
  Layers,
  FileText,
  CheckCircle2,
  Globe,
  AlertCircle,
  Shield,
  RotateCcw,
  Copy,
  Download,
  AlertOctagon,
} from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { DashboardCard } from '../components/DashboardCard';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { useSocketEvent } from '../hooks/useSocketEvent';
import {
  fetchIncidentDetail,
  fetchIncidentTimeline,
  fetchIncidentSummary,
  acknowledgeIncident,
  resolveIncident,
  closeIncident,
  reopenIncident,
} from '../services/api';
import {
  formatFullTime,
  getRiskBadgeClass,
  getIncidentStatusBadgeClass,
  getReputationBadgeClass,
} from '../utils/formatters';

export default function IncidentDetail() {
  const { incidentId } = useParams();
  const navigate = useNavigate();

  const [incident, setIncident] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [summaryReport, setSummaryReport] = useState(null);
  const [activeTab, setActiveTab] = useState('timeline');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Operator Actions state
  const [analystNote, setAnalystNote] = useState('');
  const [resolutionNote, setResolutionNote] = useState('');
  const [actionLoading, setActionLoading] = useState(false);
  const [copyFeedback, setCopyFeedback] = useState(false);

  const loadData = useCallback(async () => {
    if (!incidentId) return;
    try {
      setError(null);
      const [detail, tl, sum] = await Promise.all([
        fetchIncidentDetail(incidentId),
        fetchIncidentTimeline(incidentId),
        fetchIncidentSummary(incidentId),
      ]);
      if (!detail) {
        throw new Error(`Incident "${incidentId}" not found.`);
      }
      setIncident(detail);
      setTimeline(tl || []);
      setSummaryReport(sum || null);
    } catch (err) {
      setError(err.message || 'Failed to load incident investigation details');
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Real-time updates for this incident
  useSocketEvent('incident_updated', (data) => {
    if (data?.incident_id === incidentId) {
      loadData();
    }
  });

  useSocketEvent('incident_status_changed', (data) => {
    if (data?.incident_id === incidentId) {
      loadData();
    }
  });

  const handleAction = async (actionType) => {
    setActionLoading(true);
    try {
      if (actionType === 'acknowledge') {
        await acknowledgeIncident(incidentId, analystNote);
      } else if (actionType === 'resolve') {
        await resolveIncident(incidentId, resolutionNote, analystNote);
      } else if (actionType === 'close') {
        await closeIncident(incidentId, resolutionNote, analystNote);
      } else if (actionType === 'reopen') {
        await reopenIncident(incidentId, analystNote);
      }
      setAnalystNote('');
      setResolutionNote('');
      await loadData();
    } catch (err) {
      alert(`Action failed: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleCopyReport = () => {
    if (!summaryReport) return;
    const reportText = `NETSENTINEL EXECUTIVE INCIDENT REPORT
====================================
Incident ID: ${incidentId}
Title: ${incident?.title || 'Security Incident'}
Status: ${incident?.status}
Severity: ${incident?.severity} (Score: ${(incident?.risk_score ?? 0).toFixed(4)})
Primary Source: ${incident?.primary_source_ip || incident?.correlation_key || 'Unknown'}
First Seen: ${summaryReport.first_seen_iso || 'N/A'}
Last Seen: ${summaryReport.last_seen_iso || 'N/A'}
Duration: ${summaryReport.duration_seconds}s
Attack Vectors: ${(summaryReport.attack_vectors || []).join(', ')}
Mitigations Applied: ${(summaryReport.mitigations_applied || []).length}
${summaryReport.analyst_note ? `\nAnalyst Notes:\n${summaryReport.analyst_note}` : ''}
`;
    navigator.clipboard.writeText(reportText);
    setCopyFeedback(true);
    setTimeout(() => setCopyFeedback(false), 2500);
  };

  const handleDownloadReport = () => {
    if (!summaryReport) return;
    const reportMarkdown = `# NetSentinel SOC Incident Investigation Report
**Incident ID:** \`${incidentId}\`  
**Generated At:** ${new Date().toISOString()}  

---

### Incident Summary
- **Title:** ${incident?.title}
- **Status:** ${incident?.status}
- **Severity:** ${incident?.severity}
- **Deterministic Risk Score:** ${(incident?.risk_score ?? 0).toFixed(4)}
- **Primary Attacker / Source:** \`${incident?.primary_source_ip || incident?.correlation_key}\`
- **Attack Domains:** ${(incident?.attack_domains || []).join(', ')}
- **Detection Vectors:** ${(incident?.detection_types || []).join(', ')}

### Timeline & Duration
- **First Seen (UTC):** ${summaryReport.first_seen_iso || '-'}
- **Last Seen (UTC):** ${summaryReport.last_seen_iso || '-'}
- **Total Duration:** ${summaryReport.duration_seconds} seconds

### Mitigations Applied
${(summaryReport.mitigations_applied || []).length === 0
  ? '_No firewall mitigations applied for this incident._'
  : summaryReport.mitigations_applied.map(m => `- **${m.action?.toUpperCase()}:** ${m.summary} (${formatFullTime(m.timestamp)})`).join('\n')
}

### Evidence Artifacts
Total evidence items: ${(incident?.evidence || []).length}
${(incident?.evidence || []).map(e => `- [${formatFullTime(e.timestamp)}] **${e.evidence_type}** (${e.severity || 'INFO'}): ${e.summary}`).join('\n')}

---
*Report generated by NetSentinel Hybrid Network & Host IDS/IPS*
`;

    const blob = new Blob([reportMarkdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incident-${incidentId}-report.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading && !incident) {
    return <LoadingState message={`Loading investigation workspace for ${incidentId}...`} />;
  }

  if (error && !incident) {
    return (
      <div className="page-container">
        <ErrorState message={error} onRetry={loadData} />
        <div style={{ marginTop: '1rem', textAlign: 'center' }}>
          <Link to="/incidents" className="btn-refresh" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}>
            <ArrowLeft size={14} /> Back to Incidents List
          </Link>
        </div>
      </div>
    );
  }

  const tiEvidence = (incident?.evidence || []).find((e) => e.evidence_type === 'THREAT_INTELLIGENCE');
  const tiMeta = tiEvidence?.metadata || null;

  return (
    <div className="page-container">
      {/* Page Header with Breadcrumb */}
      <PageHeader
        title={incident.title || `Incident ${incidentId}`}
        subtitle={`ID: ${incidentId} | Target: ${incident.primary_source_ip || incident.correlation_key || 'Unknown'} | Risk Score: ${(incident.risk_score ?? 0).toFixed(2)}`}
        backLink="/incidents"
        actions={
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <span className={getIncidentStatusBadgeClass(incident.status)}>
              {incident.status}
            </span>
            <span className={getRiskBadgeClass(incident.severity)}>
              {incident.severity}
            </span>
            <button className="btn-refresh" onClick={loadData} title="Refresh Workspace">
              <RotateCcw size={14} />
            </button>
          </div>
        }
      />

      {/* Correlation Reason Callout */}
      {incident.correlation_reason && (
        <div
          style={{
            marginBottom: '1rem',
            padding: '0.75rem 1rem',
            backgroundColor: 'rgba(56, 189, 248, 0.08)',
            border: '1px solid rgba(56, 189, 248, 0.25)',
            borderRadius: '6px',
            fontSize: '0.8rem',
            color: '#bae6fd',
            lineHeight: 1.4,
          }}
        >
          <div style={{ fontWeight: 700, marginBottom: '0.25rem', color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <AlertCircle size={15} /> Incident Correlation Context
          </div>
          {incident.correlation_reason}
        </div>
      )}

      {/* Investigation Workspace Tabs */}
      <div className="investigation-tabs-nav" style={{ marginBottom: '1rem' }}>
        <button
          className={`investigation-tab-btn ${activeTab === 'timeline' ? 'active' : ''}`}
          onClick={() => setActiveTab('timeline')}
        >
          <Clock size={14} /> Unified Timeline ({timeline.length})
        </button>
        <button
          className={`investigation-tab-btn ${activeTab === 'context' ? 'active' : ''}`}
          onClick={() => setActiveTab('context')}
        >
          <Layers size={14} /> Attack Context & Vectors
        </button>
        <button
          className={`investigation-tab-btn ${activeTab === 'evidence' ? 'active' : ''}`}
          onClick={() => setActiveTab('evidence')}
        >
          <FileText size={14} /> Evidence Artifacts ({incident.evidence?.length ?? 0})
        </button>
        <button
          className={`investigation-tab-btn ${activeTab === 'report' ? 'active' : ''}`}
          onClick={() => setActiveTab('report')}
        >
          <CheckCircle2 size={14} /> Executive SOC Report
        </button>
        <button
          className={`investigation-tab-btn ${activeTab === 'threat-intel' ? 'active' : ''}`}
          onClick={() => setActiveTab('threat-intel')}
        >
          <Globe size={14} /> Threat Intelligence
        </button>
      </div>

      {/* Tab Body */}
      <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr', gap: '1rem' }}>
        {/* Tab 1: Timeline */}
        {activeTab === 'timeline' && (
          <DashboardCard title={`Chronological Attack Timeline (${timeline.length} milestones)`} icon={Clock}>
            <div className="timeline-container">
              {timeline.length === 0 ? (
                <EmptyState message="No timeline events registered for this incident." icon={Clock} />
              ) : (
                timeline.map((item, idx) => (
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
          </DashboardCard>
        )}

        {/* Tab 2: Attack Context */}
        {activeTab === 'context' && (
          <DashboardCard title="Attack Progression & Profile" icon={Layers}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.85rem' }}>
              <div className="host-section-block">
                <div className="host-block-title">Attacker & Target Identification</div>
                <div className="host-stat-row">
                  <span>Correlation Key:</span>
                  <span className="host-stat-val" style={{ fontFamily: 'monospace', color: '#38bdf8' }}>{incident.correlation_key}</span>
                </div>
                <div className="host-stat-row">
                  <span>Primary Source IP:</span>
                  <span className="host-stat-val" style={{ fontFamily: 'monospace', color: '#f8fafc' }}>{incident.primary_source_ip || 'Internal Host Identity'}</span>
                </div>
                <div className="host-stat-row">
                  <span>Attack Domains:</span>
                  <span className="host-stat-val">{(incident.attack_domains || []).join(', ') || 'network'}</span>
                </div>
                <div className="host-stat-row">
                  <span>Detection Vectors:</span>
                  <span className="host-stat-val">{(incident.detection_types || []).join(', ')}</span>
                </div>
              </div>

              <div className="host-section-block">
                <div className="host-block-title">Deterministic Risk Scoring Breakdown</div>
                <div className="host-stat-row">
                  <span>Calculated Risk Score:</span>
                  <span className="host-stat-val" style={{ color: incident.risk_score >= 0.8 ? '#f43f5e' : '#38bdf8', fontWeight: 700 }}>
                    {(incident.risk_score ?? 0).toFixed(4)}
                  </span>
                </div>
                <div className="host-stat-row">
                  <span>Severity Classification:</span>
                  <span className="host-stat-val">{incident.severity}</span>
                </div>
                <div className="host-stat-row">
                  <span>Correlated Security Events:</span>
                  <span className="host-stat-val">{incident.event_count}</span>
                </div>
                <div className="host-stat-row">
                  <span>Mitigation Actions Enforced:</span>
                  <span className="host-stat-val">{incident.firewall_action_count}</span>
                </div>
              </div>

              {incident.analyst_note && (
                <div className="host-section-block">
                  <div className="host-block-title">Current Analyst Notes</div>
                  <div style={{ color: '#cbd5e1', fontSize: '0.8rem', lineHeight: 1.5 }}>
                    {incident.analyst_note}
                  </div>
                </div>
              )}
            </div>
          </DashboardCard>
        )}

        {/* Tab 3: Evidence */}
        {activeTab === 'evidence' && (
          <DashboardCard title={`Evidence Artifacts (${(incident.evidence || []).length})`} icon={FileText}>
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
                  {(incident.evidence || []).length === 0 ? (
                    <tr>
                      <td colSpan={6} className="history-empty-row">
                        No evidence artifacts attached to this incident.
                      </td>
                    </tr>
                  ) : (
                    (incident.evidence || []).map((e) => (
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
                        <td style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
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
          </DashboardCard>
        )}

        {/* Tab 4: SOC Report Summary */}
        {activeTab === 'report' && (
          <DashboardCard
            title="SOC Executive Incident Report"
            icon={CheckCircle2}
            actions={
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <button
                  className="btn-refresh"
                  onClick={handleCopyReport}
                  title="Copy Report to Clipboard"
                >
                  <Copy size={13} /> {copyFeedback ? 'Copied!' : 'Copy Summary'}
                </button>
                <button
                  className="btn-refresh"
                  style={{ borderColor: 'var(--accent-blue)', color: 'var(--accent-blue)' }}
                  onClick={handleDownloadReport}
                  title="Download Markdown Report"
                >
                  <Download size={13} /> Download Markdown
                </button>
              </div>
            }
          >
            {!summaryReport ? (
              <EmptyState message="Generating executive summary report..." icon={CheckCircle2} />
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.85rem' }}>
                <div className="host-section-block">
                  <div className="host-block-title">Executive Summary Overview</div>
                  <div className="host-stat-row">
                    <span>First Seen (UTC):</span>
                    <span className="host-stat-val">{summaryReport.first_seen_iso || '-'}</span>
                  </div>
                  <div className="host-stat-row">
                    <span>Last Seen (UTC):</span>
                    <span className="host-stat-val">{summaryReport.last_seen_iso || '-'}</span>
                  </div>
                  <div className="host-stat-row">
                    <span>Attack Duration:</span>
                    <span className="host-stat-val">{summaryReport.duration_seconds} seconds</span>
                  </div>
                  <div className="host-stat-row">
                    <span>Attack Vectors:</span>
                    <span className="host-stat-val">{(summaryReport.attack_vectors || []).join(', ')}</span>
                  </div>
                  <div className="host-stat-row">
                    <span>Mitigations Applied:</span>
                    <span className="host-stat-val">{(summaryReport.mitigations_applied || []).length} action(s)</span>
                  </div>
                </div>

                {(summaryReport.mitigations_applied || []).length > 0 && (
                  <div className="host-section-block">
                    <div className="host-block-title">Enforced Mitigations</div>
                    {summaryReport.mitigations_applied.map((m, idx) => (
                      <div key={idx} className="host-stat-row" style={{ padding: '0.25rem 0' }}>
                        <span style={{ color: '#f43f5e', fontWeight: 600 }}>{(m.action || 'action').toUpperCase()}</span>
                        <span>{m.summary} ({formatFullTime(m.timestamp)})</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </DashboardCard>
        )}

        {/* Tab 5: Threat Intelligence */}
        {activeTab === 'threat-intel' && (
          <DashboardCard title="External Threat Intelligence Correlation" icon={Globe}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
              {!tiMeta ? (
                <div style={{ padding: '1.5rem', color: '#94a3b8', textAlign: 'center' }}>
                  <p>No threat intelligence evidence has been recorded for source IP <code>{incident.primary_source_ip || 'N/A'}</code>.</p>
                  <p style={{ fontSize: '0.75rem', marginTop: '0.5rem', color: '#64748b' }}>
                    External reputation checks are triggered asynchronously for public IPv4/IPv6 indicators when configured.
                  </p>
                </div>
              ) : (
                <div className="host-section-block">
                  <div className="host-block-title" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <Globe size={15} color="#38bdf8" />
                    External Indicator Reputation
                  </div>
                  <div className="host-stat-row">
                    <span>Assessed Source IP:</span>
                    <span className="host-stat-val" style={{ fontFamily: 'monospace', color: '#38bdf8' }}>{tiMeta.ip}</span>
                  </div>
                  <div className="host-stat-row">
                    <span>Consensus Reputation:</span>
                    <span className={`badge ${getReputationBadgeClass(tiMeta.reputation)}`}>
                      {tiMeta.reputation}
                    </span>
                  </div>
                  <div className="host-stat-row">
                    <span>Consensus Verdict:</span>
                    <span className="host-stat-val">{tiMeta.consensus}</span>
                  </div>
                  <div className="host-stat-row">
                    <span>Confidence Score:</span>
                    <span className="host-stat-val">{(tiMeta.confidence * 100).toFixed(1)}%</span>
                  </div>
                  <div className="host-stat-row">
                    <span>Autonomous System (ASN):</span>
                    <span className="host-stat-val">{tiMeta.asn || 'N/A'}</span>
                  </div>
                  <div className="host-stat-row">
                    <span>Country:</span>
                    <span className="host-stat-val">{tiMeta.country_code || 'N/A'}</span>
                  </div>
                  <div className="host-stat-row">
                    <span>Freshness:</span>
                    <span className="host-stat-val">{tiMeta.is_stale ? 'Stale / Expired' : 'Fresh'}</span>
                  </div>

                  {tiMeta.provider_results && Object.keys(tiMeta.provider_results).length > 0 && (
                    <div style={{ marginTop: '0.75rem' }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.4rem' }}>
                        Provider Observations
                      </div>
                      <div className="ti-provider-results-list">
                        {Object.entries(tiMeta.provider_results).map(([providerName, pRes]) => (
                          <div key={providerName} className="ti-provider-card">
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.3rem' }}>
                              <span style={{ fontWeight: 600, textTransform: 'capitalize' }}>{providerName}</span>
                              <span className={`badge ${getReputationBadgeClass(pRes?.reputation)}`}>
                                {pRes?.reputation || 'UNKNOWN'}
                              </span>
                            </div>
                            <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>
                              Score: {pRes?.score !== null && pRes?.score !== undefined ? `${pRes.score}/100` : 'N/A'} | Malicious: {pRes?.malicious_votes ?? 0} | Suspicious: {pRes?.suspicious_votes ?? 0}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="ti-disclaimer" style={{ marginTop: '0.75rem' }}>
                    Threat intelligence provides external contextual correlation and does not constitute absolute proof of compromise.
                  </div>
                </div>
              )}
            </div>
          </DashboardCard>
        )}
      </div>

      {/* Operator Action Controls Panel */}
      <div className="investigation-actions-panel" style={{ marginTop: '1.25rem' }}>
        <div className="action-inputs-row">
          <input
            type="text"
            className="action-text-input"
            placeholder="Add analyst investigation note..."
            value={analystNote}
            onChange={(e) => setAnalystNote(e.target.value)}
          />
          <input
            type="text"
            className="action-text-input"
            placeholder="Resolution summary (e.g. Block applied, harmless scan dismissed)..."
            value={resolutionNote}
            onChange={(e) => setResolutionNote(e.target.value)}
          />
        </div>

        <div className="action-buttons-row">
          {incident.status === 'OPEN' && (
            <button
              className="btn-action-ack"
              disabled={actionLoading}
              onClick={() => handleAction('acknowledge')}
            >
              Acknowledge Incident
            </button>
          )}

          {incident.status !== 'RESOLVED' && incident.status !== 'CLOSED' && (
            <button
              className="btn-action-resolve"
              disabled={actionLoading}
              onClick={() => handleAction('resolve')}
            >
              Mark Resolved
            </button>
          )}

          {incident.status !== 'CLOSED' && (
            <button
              className="btn-action-close"
              disabled={actionLoading}
              onClick={() => handleAction('close')}
            >
              Close Incident
            </button>
          )}

          {(incident.status === 'RESOLVED' || incident.status === 'CLOSED') && (
            <button
              className="btn-action-reopen"
              disabled={actionLoading}
              onClick={() => handleAction('reopen')}
            >
              Reopen Incident
            </button>
          )}

          <span style={{ marginLeft: 'auto', fontSize: '0.75rem', color: '#94a3b8' }}>
            Current Status: <strong style={{ color: '#f8fafc' }}>{incident.status}</strong>
          </span>
        </div>
      </div>
    </div>
  );
}
