import React from 'react';
import { Activity, User, LogOut } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export function Topbar({ apiConnected, socketConnected, readiness, onMenuClick }) {
  const isReady = readiness?.ready === true;
  const { user, logout, isAuthenticated } = useAuth();

  const getRoleBadgeStyle = (role) => {
    switch (String(role).toUpperCase()) {
      case 'ADMIN':
        return {
          backgroundColor: 'rgba(239, 68, 68, 0.12)',
          color: '#f87171',
          border: '1px solid rgba(239, 68, 68, 0.3)',
        };
      case 'ANALYST':
        return {
          backgroundColor: 'rgba(56, 189, 248, 0.12)',
          color: '#38bdf8',
          border: '1px solid rgba(56, 189, 248, 0.3)',
        };
      default: // VIEWER
        return {
          backgroundColor: 'rgba(148, 163, 184, 0.12)',
          color: '#cbd5e1',
          border: '1px solid rgba(148, 163, 184, 0.25)',
        };
    }
  };

  return (
    <header className="app-topbar">
      <div className="topbar-left">
        <button
          className="mobile-menu-btn"
          onClick={onMenuClick}
          aria-label="Toggle navigation menu"
        >
          <Activity size={18} />
        </button>
        <div className="topbar-title-group">
          <span className="topbar-title">SOC Operations Console</span>
          <span className="topbar-subtitle">Real-time Hybrid Intrusion Detection &amp; Prevention</span>
        </div>
      </div>

      <div className="topbar-status-group">
        <div className="status-pill" title="Readiness probe (/api/ready)">
          <span className="status-label">Engine:</span>
          <span className={`status-indicator ${isReady ? 'connected' : readiness ? 'warning' : 'disconnected'}`}>
            <span className="status-dot"></span>
            {isReady ? 'READY' : readiness ? 'DEGRADED' : 'CHECKING'}
          </span>
        </div>

        <div className="status-pill" title="Backend REST API connectivity">
          <span className="status-label">API:</span>
          <span className={`status-indicator ${apiConnected ? 'connected' : 'disconnected'}`}>
            <span className="status-dot"></span>
            {apiConnected ? 'Live' : 'Offline'}
          </span>
        </div>

        <div className="status-pill" title="Real-time WebSocket event stream">
          <span className="status-label">Stream:</span>
          <span className={`status-indicator ${socketConnected ? 'connected' : 'disconnected'}`}>
            <span className="status-dot"></span>
            {socketConnected ? 'Online' : 'Offline'}
          </span>
        </div>

        {isAuthenticated && user && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            marginLeft: '0.5rem',
            paddingLeft: '0.65rem',
            borderLeft: '1px solid #1e293b',
          }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              fontSize: '0.8rem',
              color: '#e2e8f0',
              fontWeight: 500,
            }}>
              <User size={13} style={{ color: '#94a3b8' }} />
              <span>{user.username}</span>
              <span style={{
                fontSize: '0.625rem',
                fontWeight: 700,
                padding: '0.12rem 0.4rem',
                borderRadius: '4px',
                letterSpacing: '0.04em',
                ...getRoleBadgeStyle(user.role),
              }}>
                {user.role}
              </span>
            </div>

            <button
              onClick={logout}
              title="Sign Out of NetSentinel"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.25rem',
                background: 'rgba(30, 41, 59, 0.6)',
                border: '1px solid #334155',
                color: '#94a3b8',
                borderRadius: '5px',
                padding: '0.25rem 0.5rem',
                fontSize: '0.72rem',
                fontWeight: 500,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
              onMouseOver={(e) => {
                e.currentTarget.style.backgroundColor = 'rgba(239, 68, 68, 0.12)';
                e.currentTarget.style.color = '#f87171';
                e.currentTarget.style.borderColor = 'rgba(239, 68, 68, 0.35)';
              }}
              onMouseOut={(e) => {
                e.currentTarget.style.backgroundColor = 'rgba(30, 41, 59, 0.6)';
                e.currentTarget.style.color = '#94a3b8';
                e.currentTarget.style.borderColor = '#334155';
              }}
            >
              <LogOut size={12} />
              <span>Sign Out</span>
            </button>
          </div>
        )}
      </div>
    </header>
  );
}

export default Topbar;
