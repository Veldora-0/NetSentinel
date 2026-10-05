/**
 * NetSentinel Socket.IO Service.
 * Manages WebSocket connection state with the Flask-SocketIO backend.
 */

import { io } from 'socket.io-client';

// Connect using relative location (Vite proxies /socket.io to http://localhost:5000)
export const socket = io({
  autoConnect: true,
  transports: ['websocket', 'polling'],
});

export function initSocketConnection(
  onConnectChange,
  onTrafficMetrics,
  onSecurityEvent,
  onMLAnomaly,
  onMLStatus,
  onRiskAssessment,
  onFirewallAction,
  onFirewallStatus,
  onBlockedIPs,
  onHostTelemetry,
  onSecuritySummary,
  onHostSecurityEvent,
  onHostStatus
) {
  socket.on('connect', () => {
    if (onConnectChange) onConnectChange(true);
  });

  socket.on('disconnect', () => {
    if (onConnectChange) onConnectChange(false);
  });

  socket.on('connect_error', () => {
    if (onConnectChange) onConnectChange(false);
  });

  if (onTrafficMetrics) {
    socket.on('traffic_metrics', (data) => {
      onTrafficMetrics(data);
    });
  }

  if (onSecurityEvent) {
    socket.on('security_event', (data) => {
      onSecurityEvent(data);
    });
  }

  if (onMLAnomaly) {
    socket.on('ml_anomaly', (data) => {
      onMLAnomaly(data);
    });
  }

  if (onMLStatus) {
    socket.on('ml_status', (data) => {
      onMLStatus(data);
    });
  }

  if (onRiskAssessment) {
    socket.on('risk_assessment', (data) => {
      onRiskAssessment(data);
    });
  }

  if (onFirewallAction) {
    socket.on('firewall_action', (data) => {
      onFirewallAction(data);
    });
  }

  if (onFirewallStatus) {
    socket.on('firewall_status', (data) => {
      onFirewallStatus(data);
    });
  }

  if (onBlockedIPs) {
    socket.on('blocked_ips', (data) => {
      onBlockedIPs(data);
    });
  }

  if (onHostTelemetry) {
    socket.on('host_telemetry', (data) => {
      onHostTelemetry(data);
    });
  }

  if (onSecuritySummary) {
    socket.on('security_summary', (data) => {
      onSecuritySummary(data);
    });
  }

  if (onHostSecurityEvent) {
    socket.on('host_security_event', (data) => {
      onHostSecurityEvent(data);
    });
  }

  if (onHostStatus) {
    socket.on('host_status', (data) => {
      onHostStatus(data);
    });
  }

  return () => {
    socket.off('connect');
    socket.off('disconnect');
    socket.off('connect_error');
    if (onTrafficMetrics) socket.off('traffic_metrics');
    if (onSecurityEvent) socket.off('security_event');
    if (onMLAnomaly) socket.off('ml_anomaly');
    if (onMLStatus) socket.off('ml_status');
    if (onRiskAssessment) socket.off('risk_assessment');
    if (onFirewallAction) socket.off('firewall_action');
    if (onFirewallStatus) socket.off('firewall_status');
    if (onBlockedIPs) socket.off('blocked_ips');
    if (onHostTelemetry) socket.off('host_telemetry');
    if (onSecuritySummary) socket.off('security_summary');
    if (onHostSecurityEvent) socket.off('host_security_event');
    if (onHostStatus) socket.off('host_status');
  };
}
