import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  AlertOctagon,
  Filter,
  Search,
  RotateCcw,
  Layers,
  ArrowRight,
  ShieldAlert,
  Clock,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { MetricCard } from '../components/common/MetricCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { DashboardCard } from '../components/DashboardCard';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { useSocketEvent } from '../hooks/useSocketEvent';
import {
  fetchIncidents,
  fetchIncidentStats,
  acknowledgeIncident,
  resolveIncident,
  closeIncident,
  reopenIncident,
} from '../services/api';
import {
  formatFullTime,
  formatAlertTime,
  formatScore,
  formatNumber,
  getRiskBadgeClass,
  getIncidentStatusBadgeClass,
} from '../utils/formatters';

export default function Incidents() {
  const navigate = useNavigate();
  const [incidents, setIncidents] = useState([]);
  const [incidentStats, setIncidentStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [actionLoading, setActionLoading] = useState(false);
  const [actionFeedback, setActionFeedback] = useState(null);

  const loadData = useCallback(async () => {
    try {
      setError(null);
      const [incRes, statsRes] = await Promise.all([
        fetchIncidents({ limit: 100 }),
        fetchIncidentStats(),
      ]);
      setIncidents(incRes?.incidents || []);
      setIncidentStats(statsRes?.stats || statsRes);
    } catch (err) {
      setError(err.message || 'Failed to load incidents');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 12000);
    return () => clearInterval(interval);
  }, [loadData]);

  // Socket.IO event updates
  useSocketEvent('incident_created', () => {
    loadData();
  });

  useSocketEvent('incident_updated', () => {
    loadData();
  });

  useSocketEvent('incident_status_changed', () => {
    loadData();
  });

  useSocketEvent('incident_stats', (data) => {
    if (data) setIncidentStats(data?.stats || data);
  });

  // Client-side filtering
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      if (statusFilter !== 'ALL' && inc.status !== statusFilter) return false;
      if (severityFilter !== 'ALL' && inc.severity !== severityFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesId = (inc.incident_id || '').toLowerCase().includes(q);
        const matchesIp = (inc.primary_source_ip || '').toLowerCase().includes(q);
        const matchesKey = (inc.correlation_key || '').toLowerCase().includes(q);
        const matchesTitle = (inc.title || '').toLowerCase().includes(q);
        if (!matchesId && !matchesIp && !matchesKey && !matchesTitle) return false;
      }
      return true;
    });
  }, [incidents, statusFilter, severityFilter, searchQuery]);

  const handleInlineAction = async (e, incidentId, action) => {
    e.stopPropagation();
    setActionLoading(true);
    setActionFeedback(null);
    try {
      if (action === 'acknowledge') {
        await acknowledgeIncident(incidentId, 'Quick acknowledged from incidents console');
        setActionFeedback({ type: 'success', text: `Incident ${incidentId} acknowledged.` });
      } else if (action === 'resolve') {
        await resolveIncident(incidentId, 'Quick resolved from console', 'Resolved by operator');
        setActionFeedback({ type: 'success', text: `Incident ${incidentId} resolved.` });
      } else if (action === 'close') {
        await closeIncident(incidentId, 'Quick closed from console', 'Closed by operator');
        setActionFeedback({ type: 'success', text: `Incident ${incidentId} closed.` });
      } else if (action === 'reopen') {
        await reopenIncident(incidentId, 'Reopened from console');
        setActionFeedback({ type: 'success', text: `Incident ${incidentId} reopened.` });
      }
      await loadData();
    } catch (err) {
      setActionFeedback({ type: 'error', text: `Action failed: ${err.message}` });
    } finally {
      setActionLoading(false);
    }
  };

  if (loading && incidents.length === 0) {
    return <LoadingState message="Loading correlated incident records..." />;
  }

  if (error && incidents.length === 0) {
    return <ErrorState message={error} onRetry={loadData} />;
  }

  const totalCount = incidentStats?.total_incidents ?? incidents.length;
  const openCount = incidentStats?.open_incidents ?? incidentStats?.open ?? incidents.filter((i) => i.status === 'OPEN').length;
  const ackCount = incidentStats?.acknowledged ?? incidents.filter((i) => i.status === 'ACKNOWLEDGED').length;
  const critCount = incidentStats?.critical_incidents ?? incidentStats?.severities?.CRITICAL ?? incidents.filter((i) => i.severity === 'CRITICAL').length;
  const resolvedCount = ((incidentStats?.resolved ?? 0) + (incidentStats?.closed ?? 0)) || incidents.filter((i) => i.status === 'RESOLVED' || i.status === 'CLOSED').length;

  return (
    <div className="page-container">
      <PageHeader
        title="Security Incidents & Investigations"
        subtitle="Correlated multi-vector security incidents tracking network attacks, host compromises, and mitigation lifecycles"
        actions={
          <button className="btn-refresh" onClick={loadData} title="Refresh Incidents">
            <RotateCcw size={14} /> Refresh
          </button>
        }
      />

      {/* KPI Cards Row */}
      <div className="metric-cards-grid">
        <MetricCard
          title="Total Incidents"
          value={formatNumber(totalCount)}
          subtext="Correlated security incidents"
          icon={AlertOctagon}
        />
        <MetricCard
          title="Open / Active"
          value={formatNumber(openCount)}
          subtext="Awaiting operator triage"
          icon={Clock}
          badge={<span className={`badge ${openCount > 0 ? 'badge-warning' : 'badge-success'}`}>{openCount > 0 ? 'ACTIVE' : 'CLEAR'}</span>}
        />
        <MetricCard
          title="Acknowledged"
          value={formatNumber(ackCount)}
          subtext="Under active investigation"
          icon={Layers}
          badge={<span className="badge badge-info">{ackCount} ACK</span>}
        />
        <MetricCard
          title="Critical Severity"
          value={formatNumber(critCount)}
          subtext="Immediate mitigation priority"
          icon={ShieldAlert}
          badge={<span className={`badge ${critCount > 0 ? 'badge-critical' : 'badge-neutral'}`}>{critCount > 0 ? 'CRITICAL' : 'ZERO'}</span>}
        />
      </div>

      {actionFeedback && (
        <div className={`safety-banner ${actionFeedback.type === 'error' ? 'danger' : 'info'}`}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {actionFeedback.type === 'error' ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}
            <span>{actionFeedback.text}</span>
          </div>
          <button onClick={() => setActionFeedback(null)} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer' }}>
            ×
          </button>
        </div>
      )}

      {/* Main Incidents Table Card */}
      <DashboardCard
        title={`Correlated Incidents (${filteredIncidents.length} displayed${incidents.length > filteredIncidents.length ? ` of ${incidents.length} total` : ''})`}
        icon={AlertOctagon}
        headerRight={
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
            <div className="incident-search-box" style={{ margin: 0 }}>
              <Search size={13} color="#64748b" />
              <input
                type="text"
                className="incident-search-input"
                placeholder="Search IP, host, title, ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <select
              className="history-filter-select"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="ALL">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="RESOLVED">Resolved</option>
              <option value="CLOSED">Closed</option>
            </select>
            <select
              className="history-filter-select"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        }
      >
        {filteredIncidents.length === 0 ? (
          <EmptyState
            title="No Incidents Found"
            message={searchQuery || statusFilter !== 'ALL' || severityFilter !== 'ALL' ? 'No incidents match your selected filters.' : 'No security incidents currently active.'}
            icon={AlertOctagon}
          />
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="soc-table">
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
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredIncidents.map((inc) => (
                  <tr
                    key={inc.incident_id}
                    style={{ cursor: 'pointer' }}
                    onClick={() => navigate(`/incidents/${encodeURIComponent(inc.incident_id)}`)}
                  >
                    <td>
                      <Link
                        to={`/incidents/${encodeURIComponent(inc.incident_id)}`}
                        style={{ color: 'var(--accent-cyan)', textDecoration: 'none', fontFamily: 'monospace', fontWeight: 600, fontSize: '0.75rem' }}
                        onClick={(e) => e.stopPropagation()}
                      >
                        {inc.incident_id}
                      </Link>
                    </td>
                    <td style={{ maxWidth: '300px' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.8rem' }}>
                        {inc.title}
                      </div>
                      <div style={{ display: 'flex', gap: '4px', marginTop: '3px', flexWrap: 'wrap' }}>
                        {(inc.detection_types || []).map((dt) => (
                          <span key={dt} className="badge badge-rule" style={{ fontSize: '0.62rem', padding: '1px 5px' }}>
                            {dt}
                          </span>
                        ))}
                        {(inc.attack_domains || []).map((dom) => (
                          <span
                            key={dom}
                            style={{
                              fontSize: '0.62rem',
                              padding: '1px 5px',
                              backgroundColor: 'rgba(56, 189, 248, 0.12)',
                              color: '#38bdf8',
                              borderRadius: '3px',
                            }}
                          >
                            {dom}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td>
                      <code style={{ color: 'var(--accent-cyan)', fontWeight: 600, fontSize: '0.78rem' }}>
                        {inc.primary_source_ip || inc.correlation_key}
                      </code>
                    </td>
                    <td>
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td>
                      <strong style={{
                        fontFamily: 'monospace',
                        color: (inc.risk_score || 0) >= 0.8 ? '#f87171' : (inc.risk_score || 0) >= 0.6 ? '#fbbf24' : '#38bdf8',
                      }}>
                        {formatScore(inc.risk_score, 2)}
                      </strong>
                    </td>
                    <td>
                      <span className={`badge ${getIncidentStatusBadgeClass(inc.status)}`}>
                        {inc.status}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                      {formatNumber(inc.event_count, 0, '0')} ev / {formatNumber(inc.firewall_action_count, 0, '0')} fw
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.74rem' }}>
                      {formatAlertTime(inc.last_seen)}
                    </td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
                        <button
                          className="btn-investigate"
                          onClick={() => navigate(`/incidents/${encodeURIComponent(inc.incident_id)}`)}
                          title="Open Investigation Workspace"
                        >
                          <Layers size={12} /> Investigate
                        </button>
                        {inc.status === 'OPEN' && (
                          <button
                            className="btn-action-ack"
                            style={{ padding: '0.2rem 0.45rem', fontSize: '0.68rem' }}
                            disabled={actionLoading}
                            onClick={(e) => handleInlineAction(e, inc.incident_id, 'acknowledge')}
                            title="Quick Acknowledge"
                          >
                            Ack
                          </button>
                        )}
                      </div>
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
