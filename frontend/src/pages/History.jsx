import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  History as HistoryIcon,
  Filter,
  Search,
  RotateCcw,
  ArrowRight,
  ShieldAlert,
  ChevronLeft,
  ChevronRight,
  Layers,
  BarChart2,
} from 'lucide-react';
import {
  ResponsiveContainer,
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
import { fetchSecurityEvents, fetchSecuritySummary } from '../services/api';
import {
  formatFullTime,
  formatAlertTime,
  formatNumber,
  formatDetectionType,
  getRiskBadgeClass,
  safeNumber,
  SEVERITY_COLORS,
} from '../utils/formatters';

export default function History() {
  const [events, setEvents] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Pagination & Filters
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(50);
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchIP, setSearchIP] = useState('');
  const [debouncedIP, setDebouncedIP] = useState('');

  // Socket throttling ref
  const lastSocketRefreshRef = useRef(0);

  // Debounce searchIP by 300ms
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedIP(searchIP);
      setPage(1); // Reset to first page on search change
    }, 300);
    return () => clearTimeout(timer);
  }, [searchIP]);

  const loadData = useCallback(async () => {
    try {
      setError(null);
      const offset = (page - 1) * limit;
      const params = { limit, offset };
      if (typeFilter !== 'ALL') params.detection_type = typeFilter;
      if (severityFilter !== 'ALL') params.severity = severityFilter;
      if (debouncedIP.trim()) params.source_ip = debouncedIP.trim();

      const [eventsRes, summaryRes] = await Promise.all([
        fetchSecurityEvents(params),
        fetchSecuritySummary(),
      ]);

      setEvents(eventsRes?.events || []);
      setTotalCount(eventsRes?.total ?? eventsRes?.events?.length ?? 0);
      if (summaryRes?.summary) setSummary(summaryRes.summary);
    } catch (err) {
      setError(err.message || 'Failed to load security event history');
    } finally {
      setLoading(false);
    }
  }, [typeFilter, severityFilter, debouncedIP, limit, page]);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [loadData]);

  // Throttled real-time socket updates (maximum once per 4 seconds)
  useSocketEvent('security_event', () => {
    const now = Date.now();
    if (now - lastSocketRefreshRef.current > 4000) {
      lastSocketRefreshRef.current = now;
      loadData();
    }
  });

  const totalPages = Math.max(1, Math.ceil(totalCount / limit));

  // Severity Distribution for Historical Chart
  const severityChartData = [
    {
      name: 'LOW',
      count: safeNumber(summary?.severities?.LOW, 0),
      color: SEVERITY_COLORS.LOW,
    },
    {
      name: 'MEDIUM',
      count: safeNumber(summary?.severities?.MEDIUM, 0),
      color: SEVERITY_COLORS.MEDIUM,
    },
    {
      name: 'HIGH',
      count: safeNumber(summary?.severities?.HIGH, 0),
      color: SEVERITY_COLORS.HIGH,
    },
    {
      name: 'CRITICAL',
      count: safeNumber(summary?.severities?.CRITICAL, 0),
      color: SEVERITY_COLORS.CRITICAL,
    },
  ];

  return (
    <div className="page-container">
      <PageHeader
        title="Security Event History & Audit Log"
        subtitle="Persisted historical audit trail of detected network threats, anomaly detections, HIDS events, and host alterations"
        actions={
          <button className="btn-refresh" onClick={loadData} title="Refresh Event History">
            <RotateCcw size={14} /> Refresh
          </button>
        }
      />

      {error && events.length === 0 && <ErrorState message={error} onRetry={loadData} />}

      {/* KPI Cards Row */}
      <div className="metric-cards-grid">
        <MetricCard
          title="Total Audit Events"
          value={formatNumber(totalCount)}
          subtext="Persisted in SQLite database"
          icon={HistoryIcon}
        />
        <MetricCard
          title="Critical Severities"
          value={formatNumber(summary?.severities?.CRITICAL ?? 0)}
          subtext="Auto-mitigation candidate events"
          icon={ShieldAlert}
          badge={
            (summary?.severities?.CRITICAL || 0) > 0 ? (
              <span className="badge badge-critical">{summary.severities.CRITICAL} CRITICAL</span>
            ) : (
              <span className="badge badge-neutral">NONE</span>
            )
          }
        />
        <MetricCard
          title="High Severities"
          value={formatNumber(summary?.severities?.HIGH ?? 0)}
          subtext="Immediate operator attention"
          icon={ShieldAlert}
          badge={<span className="badge badge-warning">{summary?.severities?.HIGH ?? 0} HIGH</span>}
        />
        <MetricCard
          title="Unique Attack Vectors"
          value={formatNumber(Object.keys(summary?.detection_types || {}).length)}
          subtext="Distinct threat classifications"
          icon={Layers}
        />
      </div>

      {/* Severity Breakdown Bar Chart */}
      {summary && (
        <DashboardCard title="Audit Event Severity Breakdown" icon={BarChart2}>
          <div style={{ height: '140px', width: '100%', marginTop: '4px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityChartData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} width={35} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                  formatter={(val) => [`${val} events`, 'Total Recorded']}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityChartData.map((entry, index) => (
                    <Cell key={`hist-cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </DashboardCard>
      )}

      {/* Filtered Audit Table Card */}
      <DashboardCard
        title={`Audit Trail Records (${events.length} displayed of ${totalCount} total)`}
        icon={HistoryIcon}
        headerRight={
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
            <div className="incident-search-box" style={{ margin: 0 }}>
              <Search size={13} color="#64748b" />
              <input
                type="text"
                className="incident-search-input"
                placeholder="Filter by source IP..."
                value={searchIP}
                onChange={(e) => setSearchIP(e.target.value)}
              />
            </div>
            <select
              className="history-filter-select"
              value={typeFilter}
              onChange={(e) => {
                setTypeFilter(e.target.value);
                setPage(1);
              }}
            >
              <option value="ALL">All Threat Types</option>
              <option value="PORT_SCAN">Port Scan</option>
              <option value="SYN_FLOOD">SYN Flood</option>
              <option value="NULL_SCAN">NULL Scan</option>
              <option value="XMAS_SCAN">XMAS Scan</option>
              <option value="ARP_SPOOFING">ARP Spoofing</option>
              <option value="ARP_IDENTITY_CONFLICT">ARP Identity Conflict</option>
              <option value="ICMP_SWEEP">ICMP Sweep</option>
              <option value="ANOMALY">ML Anomaly</option>
              <option value="SSH_AUTH_FAILURE">SSH Auth Failure</option>
              <option value="SSH_BRUTE_FORCE">SSH Brute-Force</option>
              <option value="SUSPICIOUS_PROCESS">Suspicious Process</option>
              <option value="FILE_MODIFIED">File Modified</option>
              <option value="FILE_CREATED">File Created</option>
              <option value="FILE_DELETED">File Deleted</option>
              <option value="FILE_REPLACED">File Replaced</option>
            </select>
            <select
              className="history-filter-select"
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(1);
              }}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
            <select
              className="history-filter-select"
              value={limit}
              onChange={(e) => {
                setLimit(Number(e.target.value));
                setPage(1);
              }}
            >
              <option value={25}>25 / page</option>
              <option value={50}>50 / page</option>
              <option value={100}>100 / page</option>
            </select>
          </div>
        }
      >
        {loading && events.length === 0 ? (
          <LoadingState message="Loading security event history from database..." />
        ) : events.length === 0 ? (
          <EmptyState
            title="No Matching Events"
            message="No security event records match the selected filters."
            icon={HistoryIcon}
          />
        ) : (
          <div>
            <div style={{ overflowX: 'auto' }}>
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Detection Type</th>
                    <th>Severity</th>
                    <th>Source Target</th>
                    <th>Destination</th>
                    <th>Evidence & Context</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((ev, idx) => (
                    <tr key={ev.event_id || idx}>
                      <td style={{ color: '#94a3b8', fontSize: '0.74rem', whiteSpace: 'nowrap' }}>
                        {formatFullTime(ev.timestamp)}
                      </td>
                      <td>
                        <span className="badge badge-rule" style={{ fontSize: '0.65rem' }}>
                          {formatDetectionType(ev.detection_type)}
                        </span>
                      </td>
                      <td>
                        <SeverityBadge severity={ev.severity} />
                      </td>
                      <td>
                        <code style={{ color: 'var(--accent-cyan)', fontWeight: 600, fontSize: '0.78rem' }}>
                          {ev.source_ip || 'local host'}
                        </code>
                      </td>
                      <td>
                        <code style={{ color: '#94a3b8', fontSize: '0.74rem' }}>
                          {ev.destination_ip ? `${ev.destination_ip}${ev.destination_port ? `:${ev.destination_port}` : ''}` : '—'}
                        </code>
                      </td>
                      <td style={{ maxWidth: '340px', fontSize: '0.78rem', color: '#cbd5e1' }}>
                        {ev.description}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Toolbar */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '12px', paddingTop: '10px', borderTop: '1px solid var(--border-color)', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              <span>
                Page {page} of {totalPages} ({totalCount} total records)
              </span>
              <div style={{ display: 'flex', gap: '6px' }}>
                <button
                  className="btn btn-secondary"
                  style={{ padding: '3px 8px', fontSize: '0.74rem' }}
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  <ChevronLeft size={13} /> Prev
                </button>
                <button
                  className="btn btn-secondary"
                  style={{ padding: '3px 8px', fontSize: '0.74rem' }}
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next <ChevronRight size={13} />
                </button>
              </div>
            </div>
          </div>
        )}
      </DashboardCard>
    </div>
  );
}
