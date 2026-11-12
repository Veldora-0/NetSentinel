import React, { useState, useEffect, useRef } from 'react';
import { Activity, User, LogOut, ChevronDown } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export function Topbar({ onMenuClick }) {
  const { user, logout, isAuthenticated } = useAuth();
  const [profileOpen, setProfileOpen] = useState(false);
  const dropdownRef = useRef(null);

  // Close profile dropdown on click outside or escape key
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setProfileOpen(false);
      }
    };
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') setProfileOpen(false);
    };

    if (profileOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [profileOpen]);

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
      </div>

      {/* Desktop User Controls */}
      <div className="topbar-status-group desktop-topbar-controls">
        {isAuthenticated && user && (
          <div className="topbar-user-block">
            <div className="user-profile-tag">
              <User size={13} style={{ color: '#94a3b8' }} />
              <span className="user-name">{user.username}</span>
              <span className="user-role-badge" style={getRoleBadgeStyle(user.role)}>
                {user.role}
              </span>
            </div>

            <button
              onClick={logout}
              title="Sign Out of NetSentinel"
              className="btn-signout"
            >
              <LogOut size={12} />
              <span>Sign Out</span>
            </button>
          </div>
        )}
      </div>

      {/* Mobile-Optimized Profile Trigger */}
      <div className="mobile-topbar-controls" ref={dropdownRef}>
        {isAuthenticated && user && (
          <div className="mobile-profile-wrapper">
            <button
              className={`mobile-profile-btn ${profileOpen ? 'active' : ''}`}
              onClick={() => setProfileOpen(!profileOpen)}
              aria-label="User Profile Menu"
              aria-expanded={profileOpen}
            >
              <User size={14} />
              <span className="mobile-profile-name">{user.username}</span>
              <ChevronDown size={12} className={`profile-chevron ${profileOpen ? 'open' : ''}`} />
            </button>

            {profileOpen && (
              <div className="mobile-profile-dropdown">
                <div className="dropdown-user-header">
                  <div className="dropdown-user-info">
                    <User size={16} className="dropdown-avatar" />
                    <div>
                      <div className="dropdown-username">{user.username}</div>
                      <span className="user-role-badge" style={getRoleBadgeStyle(user.role)}>
                        {user.role}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="dropdown-divider" />

                <button
                  onClick={() => {
                    setProfileOpen(false);
                    logout();
                  }}
                  className="dropdown-signout-btn"
                >
                  <LogOut size={14} />
                  <span>Sign Out</span>
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </header>
  );
}

export default Topbar;