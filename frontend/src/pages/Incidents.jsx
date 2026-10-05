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

  const loadData = useCallback(async () => {
    try {
      setError(null);
      const [incRes, statsRes] = await Promise.all([
        fetchIncidents({ limit: 100 }),
        fetchIncidentStats(),
      ]);
      setIncidents(incRes?.incidents || []);
      setIncidentStats(statsRes);
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
    if (data) setIncidentStats(data);
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
    try {
      if (action === 'acknowledge') {
        await acknowledgeIncident(incidentId, 'Quick acknowledged from incidents console');
      } else if (action === 'resolve') {
        await resolveIncident(incidentId, 'Quick resolved from console', 'Resolved by operator');
      } else if (action === 'close') {
        await closeIncident(incidentId, 'Quick closed from console', 'Closed by operator');
      } else if (action === 'reopen') {
        await reopenIncident(incidentId, 'Reopened from console');
      }
      await loadData();
    } catch (err) {
      alert(`Action failed: ${err.message}`);
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
  const openCount = incidentStats?.open ?? incidents.filter((i) => i.status === 'OPEN').length;
  const ackCount = incidentStats?.acknowledged ?? incidents.filter((i) => i.status === 'ACKNOWLEDGED').length;
  const critCount = incidentStats?.severities?.CRITICAL ?? incidents.filter((i) => i.severity === 'CRITICAL').length;
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
      <div className="incident-kpis-grid" style={{ marginBottom: '1.25rem' }}>
        <div className="incident-kpi-card">
          <span className="incident-kpi-label">Total Incidents</span>
          <span className="incident-kpi-value">{totalCount}</span>
        </div>
        <div className="incident-kpi-card">
          <span className="incident-kpi-label">Open / Active</span>
          <span className="incident-kpi-value open">{openCount}</span>
        </div>
        <div className="incident-kpi-card">
          <span className="incident-kpi-label">Acknowledged</span>
          <span className="incident-kpi-value" style={{ color: '#fbbf24' }}>
            {ackCount}
          </span>
        </div>
        <div className="incident-kpi-card">
          <span className="incident-kpi-label">Critical Severity</span>
          <span className="incident-kpi-value critical">{critCount}</span>
        </div>
        <div className="incident-kpi-card">
          <span className="incident-kpi-label">Resolved / Closed</span>
          <span className="incident-kpi-value resolved">{resolvedCount}</span>
        </div>
      </div>

      {/* Main Incidents Table Card */}
      <DashboardCard
        title={`Correlated Incidents (${filteredIncidents.length} matching of ${incidents.length} total)`}
        icon={AlertOctagon}
      >
        <div className="telemetry-card-container">
          {/* Filter Toolbar */}
          <div className="incident-toolbar">
            <div className="incident-filters">
              <Filter size={14} color="#64748b" />
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

              <div className="incident-search-box">
                <Search size={13} color="#64748b" />
                <input
                  type="text"
                  className="incident-search-input"
                  placeholder="Search IP, host, or ID..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>
            </div>
          </div>

          {/* Table */}
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
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredIncidents.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="history-empty-row">
                      No correlated security incidents match the current criteria.
                    </td>
                  </tr>
                ) : (
                  filteredIncidents.map((inc) => (
                    <tr
                      key={inc.incident_id}
                      style={{ cursor: 'pointer' }}
                      onClick={() => navigate(`/incidents/${inc.incident_id}`)}
                    >
                      <td style={{ fontFamily: 'monospace', color: '#94a3b8', fontSize: '0.7rem' }}>
                        <Link
                          to={`/incidents/${inc.incident_id}`}
                          style={{ color: '#38bdf8', textDecoration: 'none' }}
                          onClick={(e) => e.stopPropagation()}
                        >
                          {inc.incident_id}
                        </Link>
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
                            <span
                              key={dom}
                              style={{
                                fontSize: '0.6rem',
                                padding: '0.1rem 0.35rem',
                                backgroundColor: 'rgba(56, 189, 248, 0.15)',
                                color: '#38bdf8',
                                borderRadius: '3px',
                              }}
                            >
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
                      <td
                        style={{
                          fontFamily: 'monospace',
                          fontWeight: 600,
                          color: (inc.risk_score || 0) >= 0.8 ? '#f43f5e' : (inc.risk_score || 0) >= 0.6 ? '#f97316' : '#38bdf8',
                        }}
                      >
                        {formatScore(inc.risk_score, 2)}
                      </td>
                      <td>
                        <span className={getIncidentStatusBadgeClass(inc.status)}>
                          {inc.status}
                        </span>
                      </td>
                      <td style={{ fontSize: '0.7rem', color: '#94a3b8' }}>
                        {formatNumber(inc.event_count, 0, '0')} ev / {formatNumber(inc.firewall_action_count, 0, '0')} fw
                      </td>
                      <td style={{ color: '#94a3b8', fontSize: '0.7rem' }}>
                        {formatFullTime(inc.last_seen)}
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <div style={{ display: 'flex', gap: '0.35rem', alignItems: 'center' }}>
                          <button
                            className="btn-investigate"
                            onClick={() => navigate(`/incidents/${inc.incident_id}`)}
                            title="Open Investigation Workspace"
                          >
                            <Layers size={12} /> Investigate
                          </button>
                          {inc.status === 'OPEN' && (
                            <button
                              className="btn-action-ack"
                              style={{ padding: '0.2rem 0.4rem', fontSize: '0.65rem' }}
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
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </DashboardCard>
    </div>
  );
}
