/**
 * NetSentinel Safe Formatting Utilities.
 * Guarantees resilient string and numeric rendering without throwing TypeError on null/undefined.
 */

/**
 * Safely parse any input into a finite number.
 * Returns `fallback` if input is null, undefined, empty, NaN, or non-finite.
 */
export function safeNumber(value, fallback = 0) {
  if (value === null || value === undefined || value === '') return fallback;
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

/**
 * Format bytes into human-readable representation (e.g. 1.5 MB).
 */
export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined || bytes === '') return '0 B';
  const num = Number(bytes);
  if (!Number.isFinite(num) || num === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(Math.abs(num)) / Math.log(k));
  const safeI = Math.min(Math.max(0, i), sizes.length - 1);
  return `${parseFloat((num / Math.pow(k, safeI)).toFixed(1))} ${sizes[safeI]}`;
}

/**
 * Format numeric value with locale separators and specified decimals.
 */
export function formatNumber(value, decimals = 0, fallback = '—') {
  if (value === null || value === undefined || value === '') return fallback;
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return num.toLocaleString(undefined, {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
}

/**
 * Format percentage string with trailing % (e.g. 85.5%).
 */
export function formatPercent(value, decimals = 1, fallback = '—') {
  if (value === null || value === undefined || value === '') return fallback;
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return `${num.toFixed(decimals)}%`;
}

/**
 * Format score (e.g. 0.85).
 */
export function formatScore(value, decimals = 2, fallback = '—') {
  if (value === null || value === undefined || value === '') return fallback;
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return num.toFixed(decimals);
}

/**
 * Format confidence percentage safely (handles both 0.0–1.0 and 0–100 scales).
 */
export function formatConfidence(value, fallback = '—') {
  if (value === null || value === undefined || value === '') return fallback;
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  const pct = num <= 1 && num > 0 ? num * 100 : num;
  return `${Math.round(pct)}%`;
}

/**
 * Format network data rate (bps or pps).
 */
export function formatRate(value, unit = 'bps') {
  if (value === null || value === undefined || value === '') return `0 ${unit}`;
  const num = Number(value);
  if (!Number.isFinite(num)) return `0 ${unit}`;

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

/**
 * Format alert time in short HH:MM:SS format.
 */
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

/**
 * Format full date and time for table rows and timelines.
 */
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

/**
 * Format seconds into human readable uptime string (e.g. 2d 4h 12m).
 */
export function formatUptime(seconds) {
  if (seconds === null || seconds === undefined || seconds === '') return '—';
  const num = Number(seconds);
  if (!Number.isFinite(num) || num < 0) return '—';
  const s = Math.floor(num);
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  const secs = s % 60;

  if (days > 0) return `${days}d ${hours}h ${minutes}m`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

/**
 * Severity class mapping.
 */
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
      return 'badge-neutral';
  }
}

/**
 * Incident status class mapping.
 */
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
      return 'badge-neutral';
  }
}

/**
 * Risk tier badge class mapping.
 */
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
      return 'badge-neutral';
  }
}

/**
 * Threat Intelligence reputation badge class mapping.
 */
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
    case 'UNAVAILABLE':
    case 'INELIGIBLE':
      return 'badge-ti-unavailable';
    default:
      return 'badge-ti-unknown';
  }
}

/**
 * Subsystem and worker lifecycle status badge class mapping.
 */
export function getWorkerStatusBadgeClass(status) {
  switch ((status || '').toUpperCase()) {
    case 'HEALTHY':
    case 'OK':
    case 'ACTIVE':
    case 'READY':
    case 'MODEL READY':
    case 'RUNNING':
    case 'VERIFIED':
      return 'badge-success';
    case 'DEGRADED':
    case 'WARNING':
    case 'CHECKING':
    case 'INITIALIZING':
    case 'COLLECTING BASELINE':
    case 'TRAINING':
    case 'AWAITING TRAFFIC':
      return 'badge-warning';
    case 'DISABLED':
    case 'STANDBY':
    case 'OFFLINE':
    case 'UNAVAILABLE':
      return 'badge-info';
    case 'FAILED':
    case 'ERROR':
    case 'CRITICAL':
    case 'DENIED':
    case 'PERMISSION_DENIED':
      return 'badge-danger';
    case 'STOPPED':
      return 'badge-secondary';
    default:
      return 'badge-neutral';
  }
}

/**
 * Standard security color palette for charts.
 */
export const SEVERITY_COLORS = {
  LOW: '#38bdf8',
  MEDIUM: '#fbbf24',
  HIGH: '#f97316',
  CRITICAL: '#ef4444',
  DEFAULT: '#64748b',
};

export const PROTOCOL_COLORS = {
  TCP: '#06b6d4',
  UDP: '#3b82f6',
  ICMP: '#a855f7',
  ARP: '#10b981',
  OTHER: '#64748b',
};

export function getSeverityColor(severity) {
  const s = (severity || '').toUpperCase();
  return SEVERITY_COLORS[s] || SEVERITY_COLORS.DEFAULT;
}

export function getProtocolColor(proto) {
  const p = (proto || '').toUpperCase();
  return PROTOCOL_COLORS[p] || PROTOCOL_COLORS.OTHER;
}

/**
 * Convert backend detection type identifier into clean operator-friendly label.
 */
export function formatDetectionType(type) {
  if (!type) return 'Unknown';
  switch (type.toUpperCase()) {
    case 'PORT_SCAN':
      return 'Port Scan';
    case 'SYN_FLOOD':
      return 'SYN Flood';
    case 'NULL_SCAN':
      return 'NULL Scan';
    case 'XMAS_SCAN':
      return 'XMAS Scan';
    case 'ICMP_SWEEP':
      return 'ICMP Sweep';
    case 'ARP_SPOOFING':
      return 'ARP Spoofing';
    case 'ARP_IDENTITY_CONFLICT':
      return 'ARP Identity Conflict';
    case 'ANOMALY':
      return 'ML Anomaly';
    case 'SSH_AUTH_FAILURE':
      return 'SSH Auth Failure';
    case 'SSH_BRUTE_FORCE':
      return 'SSH Brute-Force';
    case 'SUSPICIOUS_PROCESS':
      return 'Suspicious Process';
    case 'FILE_MODIFIED':
      return 'File Modified (FIM)';
    case 'FILE_CREATED':
      return 'File Created (FIM)';
    case 'FILE_DELETED':
      return 'File Deleted (FIM)';
    case 'FILE_REPLACED':
      return 'File Replaced (FIM)';
    default:
      return type
        .replace(/_/g, ' ')
        .toLowerCase()
        .replace(/\b\w/g, (c) => c.toUpperCase());
  }
}
