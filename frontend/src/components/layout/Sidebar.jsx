import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Activity,
  Radio,
  ShieldCheck,
  Terminal,
  AlertOctagon,
  Globe,
  Shield,
  History,
  Server,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';

const NAV_ITEMS = [
  { path: '/overview', label: 'Overview', icon: Activity },
  { path: '/network', label: 'Network', icon: Radio },
  { path: '/detection', label: 'Detection & Risk', icon: ShieldCheck },
  { path: '/host', label: 'Host Security', icon: Terminal },
  { path: '/incidents', label: 'Incidents', icon: AlertOctagon },
  { path: '/threat-intelligence', label: 'Threat Intel', icon: Globe },
  { path: '/firewall', label: 'Firewall', icon: Shield },
  { path: '/history', label: 'Security History', icon: History },
  { path: '/system', label: 'System Status', icon: Server },
];

export function Sidebar({ collapsed, onToggleCollapse }) {
  return (
    <aside className={`app-sidebar ${collapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-brand">
        <Shield className="sidebar-brand-icon" size={24} />
        {!collapsed && (
          <div className="sidebar-brand-text">
            <span className="brand-name">NetSentinel</span>
            <span className="brand-version">v1.0.0</span>
          </div>
        )}
      </div>

      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `sidebar-nav-item ${isActive ? 'active' : ''}`
              }
              title={collapsed ? item.label : undefined}
            >
              <Icon size={18} className="nav-icon" />
              {!collapsed && <span className="nav-label">{item.label}</span>}
            </NavLink>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <button
          className="collapse-toggle-btn"
          onClick={onToggleCollapse}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
          {!collapsed && <span>Collapse</span>}
        </button>
      </div>
    </aside>
  );
}
