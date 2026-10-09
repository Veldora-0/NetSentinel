/**
 * NetSentinel REST API Service.
 * Interacts with the Flask backend API via relative endpoint paths (proxied by Vite).
 */

export function getAuthHeaders(customHeaders = {}) {
  const headers = { 'Accept': 'application/json', ...customHeaders };
  try {
    const token =
      localStorage.getItem('token') ||
      localStorage.getItem('netsentinel_token') ||
      sessionStorage.getItem('token');
    if (token && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${token}`;
    }
  } catch {
    // Ignore storage errors in restricted contexts
  }
  return headers;
}

export async function authFetch(url, options = {}) {
  const customHeaders = options.headers || {};
  const headers = getAuthHeaders(customHeaders);
  return fetch(url, { ...options, headers });
}

async function parseResponseOrError(response) {
  let data = null;
  try {
    data = await response.json();
  } catch {
    // Non-JSON or empty response
  }

  if (!response.ok) {
    const errorMsg = data?.message || data?.error || `HTTP Error ${response.status}`;
    const err = new Error(errorMsg);
    err.status = response.status;
    err.code = response.status;
    err.data = data;
    throw err;
  }

  return data;
}

export async function checkBackendHealth() {
  try {
    const response = await authFetch('/api/health', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return {
      connected: true,
      data: data,
    };
  } catch (error) {
    return {
      connected: false,
      error: error.message,
    };
  }
}

export async function fetchTrafficMetrics() {
  try {
    const response = await authFetch('/api/metrics', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return null;
  }
}

export async function fetchSecurityAlerts(limit = 50) {
  try {
    const response = await authFetch(`/api/alerts?limit=${limit}`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return data.alerts || [];
  } catch (error) {
    return [];
  }
}

export async function fetchMLStatus() {
  try {
    const response = await authFetch('/api/ml/status', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return null;
  }
}

export async function fetchMLMetrics() {
  try {
    const response = await authFetch('/api/ml/metrics', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return null;
  }
}

export async function fetchRecentRisks(limit = 20) {
  try {
    const response = await authFetch(`/api/risk/recent?limit=${limit}`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return data.assessments || [];
  } catch (error) {
    return [];
  }
}

export async function fetchRiskStats() {
  try {
    const response = await authFetch('/api/risk/stats', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return data.stats || null;
  } catch (error) {
    return null;
  }
}

export async function fetchFirewallStatus() {
  try {
    const response = await authFetch('/api/firewall/status', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return data.firewall || null;
  } catch (error) {
    return null;
  }
}

export async function fetchBlockedIPs() {
  try {
    const response = await authFetch('/api/firewall/blocked', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return data.blocked_ips || [];
  } catch (error) {
    return [];
  }
}

export async function manualBlockIP(ip, reason = 'Operator Manual Block', duration = 300) {
  try {
    const response = await authFetch('/api/firewall/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ ip, reason: reason || 'Operator Manual Block', duration: Number(duration) || 300 }),
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { status: 'error', message: error.message };
  }
}

export async function manualUnblockIP(ip) {
  try {
    const response = await authFetch('/api/firewall/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ ip }),
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { status: 'error', message: error.message };
  }
}

// Phase 6: Historical Reporting & Host Telemetry APIs

export async function fetchSecurityEvents(params = {}) {
  try {
    const query = new URLSearchParams();
    if (params.limit) query.append('limit', params.limit);
    if (params.offset) query.append('offset', params.offset);
    if (params.since) query.append('since', params.since);
    if (params.until) query.append('until', params.until);
    if (params.source_ip) query.append('source_ip', params.source_ip);
    if (params.detection_type) query.append('detection_type', params.detection_type);
    if (params.severity) query.append('severity', params.severity);

    const qs = query.toString();
    const url = qs ? `/api/events?${qs}` : '/api/events';
    const response = await authFetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { status: 'error', total: 0, count: 0, events: [], error: error.message };
  }
}

export async function fetchRiskHistory(params = {}) {
  try {
    const query = new URLSearchParams();
    if (params.limit) query.append('limit', params.limit);
    if (params.offset) query.append('offset', params.offset);
    if (params.since) query.append('since', params.since);
    if (params.until) query.append('until', params.until);
    if (params.source_ip) query.append('source_ip', params.source_ip);
    if (params.risk_level) query.append('risk_level', params.risk_level);

    const qs = query.toString();
    const url = qs ? `/api/risk/history?${qs}` : '/api/risk/history';
    const response = await authFetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { status: 'error', total: 0, count: 0, assessments: [], error: error.message };
  }
}

export async function fetchSecuritySummary(since = null) {
  try {
    const url = since ? `/api/security/summary?since=${since}` : '/api/security/summary';
    const response = await authFetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return data.summary || null;
  } catch (error) {
    return null;
  }
}

export async function fetchTelemetryCurrent() {
  try {
    const response = await authFetch('/api/telemetry/current', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return data.telemetry || null;
  } catch (error) {
    return null;
  }
}

export async function fetchTelemetryHistory(limit = 60, since = null, until = null) {
  try {
    const query = new URLSearchParams();
    if (limit) query.append('limit', limit);
    if (since) query.append('since', since);
    if (until) query.append('until', until);

    const qs = query.toString();
    const url = qs ? `/api/telemetry/history?${qs}` : '/api/telemetry/history';
    const response = await authFetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return data.telemetry || [];
  } catch (error) {
    return [];
  }
}

// Phase 7: Host-Based Intrusion Detection (HIDS) APIs

export async function fetchHostStatus() {
  try {
    const response = await authFetch('/api/host/status', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return data.host || null;
  } catch (error) {
    return null;
  }
}

export async function fetchHostEvents(params = {}) {
  try {
    const query = new URLSearchParams();
    if (params.limit) query.append('limit', params.limit);
    if (params.offset) query.append('offset', params.offset);
    if (params.since) query.append('since', params.since);
    if (params.until) query.append('until', params.until);
    if (params.source_ip) query.append('source_ip', params.source_ip);
    if (params.detection_type) query.append('detection_type', params.detection_type);
    if (params.severity) query.append('severity', params.severity);

    const qs = query.toString();
    const url = qs ? `/api/host/events?${qs}` : '/api/host/events';
    const response = await authFetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { status: 'error', total: 0, count: 0, events: [], error: error.message };
  }
}

// Phase 8: Advanced Network Threat Detection APIs

export async function fetchNetworkStatus() {
  try {
    const response = await authFetch('/api/network/status', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return null;
  }
}

export async function fetchARPMappings(limit = 100) {
  try {
    const response = await authFetch(`/api/network/arp?limit=${limit}`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { status: 'error', total: 0, count: 0, mappings: [], error: error.message };
  }
}

// Phase 9: Incident Correlation & Investigation APIs

export async function fetchIncidents(params = {}) {
  try {
    const query = new URLSearchParams();
    if (params.limit) query.append('limit', params.limit);
    if (params.offset) query.append('offset', params.offset);
    if (params.since) query.append('since', params.since);
    if (params.until) query.append('until', params.until);
    if (params.status) query.append('status', params.status);
    if (params.severity) query.append('severity', params.severity);
    if (params.source_ip) query.append('source_ip', params.source_ip);
    if (params.correlation_key) query.append('correlation_key', params.correlation_key);

    const qs = query.toString();
    const url = qs ? `/api/incidents?${qs}` : '/api/incidents';
    const response = await authFetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { status: 'error', total: 0, count: 0, incidents: [], error: error.message };
  }
}

export async function fetchIncidentStats(since = null) {
  try {
    const url = since ? `/api/incidents/stats?since=${since}` : '/api/incidents/stats';
    const response = await authFetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return data.stats || null;
  } catch (error) {
    return null;
  }
}

export async function fetchIncidentDetail(incidentId) {
  if (!incidentId) return null;
  try {
    const response = await authFetch(`/api/incidents/${encodeURIComponent(incidentId)}`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return data.incident || null;
  } catch (error) {
    return null;
  }
}

export async function fetchIncidentTimeline(incidentId) {
  if (!incidentId) return [];
  try {
    const response = await authFetch(`/api/incidents/${encodeURIComponent(incidentId)}/timeline`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return data.timeline || [];
  } catch (error) {
    return [];
  }
}

export async function fetchIncidentSummary(incidentId) {
  if (!incidentId) return null;
  try {
    const response = await authFetch(`/api/incidents/${encodeURIComponent(incidentId)}/summary`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return data.summary || null;
  } catch (error) {
    return null;
  }
}

export async function updateIncidentStatus(incidentId, status, analystNote = '', resolution = '') {
  try {
    const response = await authFetch(`/api/incidents/${encodeURIComponent(incidentId)}/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ status, analyst_note: analystNote, resolution }),
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { status: 'error', message: error.message };
  }
}

export async function acknowledgeIncident(incidentId, analystNote = '') {
  try {
    const response = await authFetch(`/api/incidents/${encodeURIComponent(incidentId)}/acknowledge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ analyst_note: analystNote }),
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { status: 'error', message: error.message };
  }
}

export async function resolveIncident(incidentId, resolution = '', analystNote = '') {
  try {
    const response = await authFetch(`/api/incidents/${encodeURIComponent(incidentId)}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ resolution, analyst_note: analystNote }),
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { status: 'error', message: error.message };
  }
}

export async function closeIncident(incidentId, resolution = '', analystNote = '') {
  try {
    const response = await authFetch(`/api/incidents/${encodeURIComponent(incidentId)}/close`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ resolution, analyst_note: analystNote }),
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { status: 'error', message: error.message };
  }
}

export async function reopenIncident(incidentId, analystNote = '') {
  try {
    const response = await authFetch(`/api/incidents/${encodeURIComponent(incidentId)}/reopen`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ analyst_note: analystNote }),
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { status: 'error', message: error.message };
  }
}

// Phase 10: File Integrity Monitoring (FIM) APIs

export async function fetchFimStatus() {
  try {
    const response = await authFetch('/api/fim/status', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { enabled: false, error: error.message };
  }
}

export async function fetchFimEvents(params = {}) {
  try {
    const query = new URLSearchParams();
    if (params.limit) query.append('limit', params.limit);
    if (params.offset) query.append('offset', params.offset);
    if (params.since) query.append('since', params.since);
    if (params.until) query.append('until', params.until);
    if (params.change_type) query.append('change_type', params.change_type);
    if (params.path) query.append('path', params.path);

    const qs = query.toString();
    const url = qs ? `/api/fim/events?${qs}` : '/api/fim/events';
    const response = await authFetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { total: 0, limit: params.limit || 50, offset: params.offset || 0, events: [], error: error.message };
  }
}

export async function fetchFimBaseline(params = {}) {
  try {
    const query = new URLSearchParams();
    if (params.limit) query.append('limit', params.limit);
    if (params.offset) query.append('offset', params.offset);
    if (params.status) query.append('status', params.status);
    if (params.path) query.append('path', params.path);

    const qs = query.toString();
    const url = qs ? `/api/fim/baseline?${qs}` : '/api/fim/baseline';
    const response = await authFetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { total: 0, limit: params.limit || 100, offset: params.offset || 0, baseline: [], error: error.message };
  }
}

export async function triggerFimRebaseline(paths = null) {
  try {
    const response = await authFetch('/api/fim/rebaseline', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(paths ? { paths } : {}),
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// ==============================================================================
// Threat Intelligence API (Phase 11)
// ==============================================================================

export async function fetchThreatIntelStatus() {
  try {
    const response = await authFetch('/api/threat-intel/status', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return data.threat_intel || null;
  } catch (error) {
    return null;
  }
}

export async function fetchThreatIntelIP(ip) {
  if (!ip) return null;
  try {
    const response = await authFetch(`/api/threat-intel/ip/${encodeURIComponent(ip)}`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return { status: 'error', available: false, error: error.message };
  }
}

export async function requestThreatIntelLookup(ip) {
  if (!ip) return { status: 'error', message: 'No IP provided' };
  try {
    const response = await authFetch(`/api/threat-intel/ip/${encodeURIComponent(ip)}/lookup`, {
      method: 'POST',
      headers: { 'Accept': 'application/json' },
    });
    const data = await parseResponseOrError(response);
    return { success: true, ...data };
  } catch (error) {
    return { success: false, message: error.message };
  }
}

// ==============================================================================
// Operational Health & Production Diagnostics API (Phase 12)
// ==============================================================================

export async function fetchReadiness() {
  try {
    const response = await authFetch('/api/ready', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await response.json().catch(() => ({}));
    return {
      ok: response.ok,
      status: response.status,
      ...data,
    };
  } catch (error) {
    return { ok: false, ready: false, error: error.message };
  }
}

export async function fetchSystemStatus() {
  try {
    const response = await authFetch('/api/system/status', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    return await parseResponseOrError(response);
  } catch (error) {
    return null;
  }
}
