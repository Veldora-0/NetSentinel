import React from 'react';
import { Shield, Radio, Activity, CheckCircle2, AlertTriangle } from 'lucide-react';

export function Topbar({ apiConnected, socketConnected, readiness, onMenuClick }) {
  const isReady = readiness?.ready === true;

  return (
    <header className="app-topbar">
      <div className="topbar-left">
        <button
          className="mobile-menu-btn"
          onClick={onMenuClick}
          aria-label="Toggle navigation menu"
        >
          <Activity size={20} />
        </button>
        <div className="topbar-title-group">
          <span className="topbar-title">SOC Operations Console</span>
          <span className="topbar-subtitle">Real-time Hybrid Intrusion Detection & Prevention</span>
        </div>
      </div>

      <div className="topbar-status-group">
        <div className="status-pill" title="Readiness probe (/api/ready)">
          <span className="status-label">Readiness:</span>
          <span className={`status-indicator ${isReady ? 'connected' : readiness ? 'warning' : 'disconnected'}`}>
            <span className="status-dot"></span>
            {isReady ? 'READY' : readiness ? 'DEGRADED' : 'CHECKING'}
          </span>
        </div>

        <div className="status-pill" title="Backend REST API connectivity">
          <span className="status-label">API:</span>
          <span className={`status-indicator ${apiConnected ? 'connected' : 'disconnected'}`}>
            <span className="status-dot"></span>
            {apiConnected ? 'Connected' : 'Offline'}
          </span>
        </div>

        <div className="status-pill" title="Real-time WebSocket event stream">
          <span className="status-label">Socket.IO:</span>
          <span className={`status-indicator ${socketConnected ? 'connected' : 'disconnected'}`}>
            <span className="status-dot"></span>
            {socketConnected ? 'Live' : 'Offline'}
          </span>
        </div>
      </div>
    </header>
  );
}
