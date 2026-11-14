import React, { useState, useEffect, useRef } from 'react';
import { Activity, User, LogOut, ChevronDown, Moon, Sun } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export function Topbar({ onMenuClick }) {
  const { user, logout, isAuthenticated } = useAuth();
  const [profileOpen, setProfileOpen] = useState(false);
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem('netsentinel_theme') === 'dark' ? 'dark' : 'light';
    } catch {
      return 'light';
    }
  });
  const dropdownRef = useRef(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem('netsentinel_theme', theme);
    } catch {
      // The theme still works for this session when browser storage is unavailable.
    }
  }, [theme]);

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

  const roleClass = `role-${String(user?.role || 'viewer').toLowerCase()}`;

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

      <div className="topbar-right">
        <button
          className="theme-toggle"
          onClick={() => setTheme((current) => current === 'dark' ? 'light' : 'dark')}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          aria-pressed={theme === 'dark'}
        >
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
          <span className="theme-toggle-label">{theme === 'dark' ? 'Light' : 'Dark'}</span>
        </button>

        {/* Desktop User Controls */}
        <div className="topbar-status-group desktop-topbar-controls">
          {isAuthenticated && user && (
            <div className="topbar-user-block">
              <div className="user-profile-tag">
                <User size={13} />
                <span className="user-name">{user.username}</span>
                <span className={`user-role-badge ${roleClass}`}>{user.role}</span>
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
                      <span className={`user-role-badge ${roleClass}`}>
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
      </div>
    </header>
  );
}

export default Topbar;
