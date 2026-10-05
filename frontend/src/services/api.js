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

