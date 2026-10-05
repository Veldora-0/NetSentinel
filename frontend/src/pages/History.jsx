import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  History as HistoryIcon,
  Filter,
  Search,
  RotateCcw,
  ArrowRight,
  ShieldAlert,
} from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { DashboardCard } from '../components/DashboardCard';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { useSocketEvent } from '../hooks/useSocketEvent';
import { fetchSecurityEvents } from '../services/api';
import { formatFullTime, getRiskBadgeClass } from '../utils/formatters';

export default function History() {
  const [events, setEvents] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchIP, setSearchIP] = useState('');
  const [limit, setLimit] = useState(100);

  const loadData = useCallback(async () => {
    try {
      setError(null);
      const params = { limit };
      if (typeFilter !== 'ALL') params.detection_type = typeFilter;
      if (severityFilter !== 'ALL') params.severity = severityFilter;
      if (searchIP.trim()) params.source_ip = searchIP.trim();

      const res = await fetchSecurityEvents(params);
      setEvents(res?.events || []);
      setTotalCount(res?.total ?? res?.events?.length ?? 0);
    } catch (err) {
      setError(err.message || 'Failed to load security event history');
    } finally {
      setLoading(false);
    }
  }, [typeFilter, severityFilter, searchIP, limit]);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [loadData]);

  // Real-time socket updates
  useSocketEvent('security_event', () => {
    loadData();
  });

  if (loading && events.length === 0) {
    return <LoadingState message="Loading security event history from database..." />;
  }

  if (error && events.length === 0) {
    return <ErrorState message={error} onRetry={loadData} />;
  }

  return (
    <div className="page-container">
      <PageHeader
        title="Security Event History"
        subtitle="Persisted audit log of detected network threats, anomaly detections, HIDS events, and host alterations"
        actions={
          <button className="btn-refresh" onClick={loadData} title="Refresh Event History">
            <RotateCcw size={14} /> Refresh
          </button>
        }
      />

      <DashboardCard
        title={`Audit Trail Records (${events.length} displayed${totalCount > events.length ? ` of ${totalCount} total` : ''})`}
        icon={HistoryIcon}
      >
        <div className="telemetry-card-container">
          {/* Filters Bar */}
          <div className="history-card-header" style={{ marginBottom: '1rem' }}>
            <div className="history-filters" style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <Filter size={14} color="#64748b" />
              <select
                className="history-filter-select"
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
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
                onChange={(e) => setSeverityFilter(e.target.value)}
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
                onChange={(e) => setLimit(Number(e.target.value))}
              >
                <option value={25}>Limit 25</option>
                <option value={50}>Limit 50</option>
                <option value={100}>Limit 100</option>
                <option value={200}>Limit 200</option>
              </select>

              <div className="incident-search-box">
                <Search size={13} color="#64748b" />
                <input
                  type="text"
                  className="history-search-input"
                  placeholder="Filter by source IP..."
                  value={searchIP}
                  onChange={(e) => setSearchIP(e.target.value)}
                />
              </div>
            </div>
          </div>

          {/* Table */}
          <div className="history-table-container">
            <table className="history-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Detection Type</th>
                  <th>Severity</th>
                  <th>Source IP</th>
                  <th>Destination</th>
                  <th>Description & Evidence</th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="history-empty-row">
                      No security event records match the selected criteria.
                    </td>
                  </tr>
                ) : (
                  events.map((ev, idx) => (
                    <tr key={ev.event_id || idx}>
                      <td style={{ color: '#94a3b8', fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                        {formatFullTime(ev.timestamp)}
                      </td>
                      <td>
                        <span className="badge badge-rule" style={{ fontSize: '0.65rem' }}>
                          {ev.detection_type}
                        </span>
                      </td>
                      <td>
                        <span className={getRiskBadgeClass(ev.severity)} style={{ fontSize: '0.65rem' }}>
                          {ev.severity}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'monospace', color: '#38bdf8', fontWeight: 600 }}>
                        {ev.source_ip || 'local host'}
                      </td>
                      <td style={{ fontFamily: 'monospace', color: '#94a3b8', fontSize: '0.75rem' }}>
                        {ev.destination_ip ? `${ev.destination_ip}${ev.destination_port ? `:${ev.destination_port}` : ''}` : '-'}
                      </td>
                      <td style={{ maxWidth: '320px', overflow: 'hidden', textOverflow: 'ellipsis', fontSize: '0.8rem' }}>
                        {ev.description}
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
