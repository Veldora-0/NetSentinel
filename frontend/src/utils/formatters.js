/**
 * NetSentinel Safe Formatting Utilities.
 * Guarantees resilient string and numeric rendering without throwing TypeError on null/undefined.
 */

export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined || isNaN(bytes)) return '0 B';
  const num = Number(bytes);
  if (num === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(num) / Math.log(k));
  const safeI = Math.min(Math.max(0, i), sizes.length - 1);
  return parseFloat((num / Math.pow(k, safeI)).toFixed(1)) + ' ' + sizes[safeI];
}

export function formatNumber(value, decimals = 0) {
  if (value === null || value === undefined || isNaN(value)) return 'N/A';
  const num = Number(value);
  return num.toLocaleString(undefined, {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
}

export function formatPercent(value, decimals = 1) {
  if (value === null || value === undefined || isNaN(value)) return 'N/A';
  const num = Number(value);
  return `${num.toFixed(decimals)}%`;
}

export function formatScore(value, decimals = 2) {
  if (value === null || value === undefined || isNaN(value)) return 'N/A';
  const num = Number(value);
  return num.toFixed(decimals);
}

export function formatRate(value, unit = 'bps') {
  if (value === null || value === undefined || isNaN(value)) return `0 ${unit}`;
  const num = Number(value);
  if (unit === 'bps') {
    if (num >= 1_000_000_000) return `${(num / 1_000_000_000).toFixed(2)} Gbps`;
    if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(2)} Mbps`;
    if (num >= 1_000) return `${(num / 1_000).toFixed(2)} Kbps`;
    return `${num.toFixed(0)} bps`;
  }
  if (unit === 'pps') {
    if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(2)} Mpps`;
    if (num >= 1_000) return `${(num / 1_000).toFixed(2)} Kpps`;
    return `${num.toFixed(0)} pps`;
  }
  return `${num.toFixed(0)} ${unit}`;
}

export function formatAlertTime(timestamp) {
  if (!timestamp) return '—';
  try {
    const d = new Date(Number(timestamp) * 1000);
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return '—';
  }
}

export function formatFullTime(timestamp) {
  if (!timestamp) return '—';
  try {
    const d = new Date(Number(timestamp) * 1000);
    if (isNaN(d.getTime())) return '—';
    return (
      d.toLocaleDateString() +
      ' ' +
      d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    );
  } catch {
    return '—';
  }
}

export function formatUptime(seconds) {
  if (seconds === null || seconds === undefined || isNaN(seconds)) return '—';
  const s = Math.floor(Number(seconds));
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  const secs = s % 60;

  if (days > 0) return `${days}d ${hours}h ${minutes}m`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

export function getSeverityBadgeClass(severity) {
  switch ((severity || '').toUpperCase()) {
    case 'CRITICAL':
      return 'badge-critical';
    case 'HIGH':
      return 'badge-high';
    case 'MEDIUM':
      return 'badge-medium';
    case 'LOW':
      return 'badge-low';
    default:
      return 'badge-info';
  }
}

export function getIncidentStatusBadgeClass(status) {
  switch ((status || '').toUpperCase()) {
    case 'OPEN':
      return 'badge-status-open';
    case 'ACKNOWLEDGED':
      return 'badge-status-acknowledged';
    case 'RESOLVED':
      return 'badge-status-resolved';
    case 'CLOSED':
      return 'badge-status-closed';
    default:
      return 'badge-info';
  }
}

export function getRiskBadgeClass(level) {
  switch ((level || '').toUpperCase()) {
    case 'CRITICAL':
      return 'badge-critical';
    case 'HIGH':
      return 'badge-high';
    case 'MEDIUM':
      return 'badge-medium';
    case 'LOW':
      return 'badge-low';
    default:
      return 'badge-low';
  }
}

export function getReputationBadgeClass(rep) {
  switch ((rep || '').toUpperCase()) {
    case 'MALICIOUS':
      return 'badge-ti-malicious';
    case 'SUSPICIOUS':
      return 'badge-ti-suspicious';
    case 'CLEAN':
      return 'badge-ti-clean';
    case 'CONFLICTING':
      return 'badge-ti-conflicting';
    default:
      return 'badge-ti-unknown';
  }
}

export function getWorkerStatusBadgeClass(status) {
  switch ((status || '').toUpperCase()) {
    case 'HEALTHY':
    case 'OK':
      return 'badge-success';
    case 'DEGRADED':
      return 'badge-warning';
    case 'DISABLED':
      return 'badge-info';
    case 'FAILED':
      return 'badge-danger';
    case 'STOPPED':
      return 'badge-secondary';
    default:
      return 'badge-info';
  }
}
