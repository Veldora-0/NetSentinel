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
