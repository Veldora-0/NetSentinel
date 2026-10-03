import React from 'react';
import { Shield } from 'lucide-react';

export function Header({ apiConnected, socketConnected }) {
  return (
    <header className="header-bar">
      <div className="header-title">
        <Shield className="header-icon" size={28} />
        <div>
          <h1>NetSentinel</h1>
          <p className="header-subtitle">Hybrid Network & Host Intrusion Prevention System</p>
        </div>
      </div>
      <div className="header-status-group">
        <div className="status-pill">
          <span className="status-label">API Status:</span>
          <span className={`status-indicator ${apiConnected ? 'connected' : 'disconnected'}`}>
            <span className="status-dot"></span>
            {apiConnected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
        <div className="status-pill">
          <span className="status-label">Socket.IO:</span>
          <span className={`status-indicator ${socketConnected ? 'connected' : 'disconnected'}`}>
            <span className="status-dot"></span>
            {socketConnected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </div>
    </header>
  );
}
