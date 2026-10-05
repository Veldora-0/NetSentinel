/**
 * NetSentinel REST API Service.
 * Interacts with the Flask backend API via relative endpoint paths (proxied by Vite).
 */

export async function checkBackendHealth() {
  try {
    const response = await fetch('/api/health', {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP Error Status: ${response.status}`);
    }

    const data = await response.json();
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
    const response = await fetch('/api/metrics', {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP Error Status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    return null;
  }
}

export async function fetchSecurityAlerts(limit = 50) {
  try {
    const response = await fetch(`/api/alerts?limit=${limit}`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP Error Status: ${response.status}`);
    }

    const data = await response.json();
    return data.alerts || [];
  } catch (error) {
    return [];
  }
}

export async function fetchMLStatus() {
  try {
    const response = await fetch('/api/ml/status', {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP Error Status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    return null;
  }
}

export async function fetchMLMetrics() {
  try {
    const response = await fetch('/api/ml/metrics', {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP Error Status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    return null;
  }
}
export async function fetchRecentRisks(limit = 20) {
  try {
    const response = await fetch(`/api/risk/recent?limit=${limit}`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
    const data = await response.json();
    return data.assessments || [];
  } catch (error) {
    return [];
  }
}

export async function fetchRiskStats() {
  try {
    const response = await fetch('/api/risk/stats', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
    const data = await response.json();
    return data.stats || null;
  } catch (error) {
    return null;
  }
}

export async function fetchFirewallStatus() {
  try {
    const response = await fetch('/api/firewall/status', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
    const data = await response.json();
    return data.firewall || null;
  } catch (error) {
    return null;
  }
}

export async function fetchBlockedIPs() {
  try {
    const response = await fetch('/api/firewall/blocked', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
    const data = await response.json();
    return data.blocked_ips || [];
  } catch (error) {
    return [];
  }
}

export async function manualBlockIP(ip, reason = 'Operator Manual Block', duration = 300) {
  try {
    const response = await fetch('/api/firewall/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ ip, reason, duration }),
    });
    return await response.json();
  } catch (error) {
    return { status: 'error', message: error.message };
  }
}

export async function manualUnblockIP(ip) {
  try {
    const response = await fetch('/api/firewall/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ ip }),
    });
    return await response.json();
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
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
    return await response.json();
  } catch (error) {
    return { status: 'error', total: 0, count: 0, events: [] };
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
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
    return await response.json();
  } catch (error) {
    return { status: 'error', total: 0, count: 0, assessments: [] };
  }
}

export async function fetchSecuritySummary(since = null) {
  try {
    const url = since ? `/api/security/summary?since=${since}` : '/api/security/summary';
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
    const data = await response.json();
    return data.summary || null;
  } catch (error) {
    return null;
  }
}

export async function fetchTelemetryCurrent() {
  try {
    const response = await fetch('/api/telemetry/current', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
    const data = await response.json();
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
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
    const data = await response.json();
    return data.telemetry || [];
  } catch (error) {
    return [];
  }
}

// Phase 7: Host-Based Intrusion Detection (HIDS) APIs

export async function fetchHostStatus() {
  try {
    const response = await fetch('/api/host/status', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
    const data = await response.json();
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
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
    return await response.json();
  } catch (error) {
    return { status: 'error', total: 0, count: 0, events: [] };
  }
}

// Phase 8: Advanced Network Threat Detection APIs

export async function fetchNetworkStatus() {
  try {
    const response = await fetch('/api/network/status', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
    return await response.json();
  } catch (error) {
    return null;
  }
}

export async function fetchARPMappings(limit = 100) {
  try {
    const response = await fetch(`/api/network/arp?limit=${limit}`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
    return await response.json();
  } catch (error) {
    return { status: 'error', total: 0, count: 0, mappings: [] };
  }
}


