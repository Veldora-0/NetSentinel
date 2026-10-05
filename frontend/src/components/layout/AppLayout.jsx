import React, { useState, useEffect } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';
import { checkBackendHealth, fetchReadiness } from '../../services/api';
import { socket } from '../../services/socket';

export function AppLayout() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [apiConnected, setApiConnected] = useState(false);
  const [socketConnected, setSocketConnected] = useState(socket?.connected || false);
  const [readiness, setReadiness] = useState(null);

  useEffect(() => {
    let isMounted = true;

    // Fast initial health and readiness check
    const checkStatus = async () => {
      try {
        const health = await checkBackendHealth();
        if (isMounted) setApiConnected(health.connected);
        const ready = await fetchReadiness();
        if (isMounted) setReadiness(ready);
      } catch {
        if (isMounted) {
          setApiConnected(false);
          setReadiness(null);
        }
      }
    };

    checkStatus();
    const interval = setInterval(checkStatus, 10000);

    const onConnect = () => setSocketConnected(true);
    const onDisconnect = () => setSocketConnected(false);

    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);

    return () => {
      isMounted = false;
      clearInterval(interval);
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
    };
  }, []);

  return (
    <div className={`app-shell ${collapsed ? 'sidebar-collapsed' : ''} ${mobileOpen ? 'mobile-open' : ''}`}>
      <Sidebar
        collapsed={collapsed}
        onToggleCollapse={() => setCollapsed(!collapsed)}
      />
      {mobileOpen && (
        <div className="mobile-overlay" onClick={() => setMobileOpen(false)} />
      )}
      <div className="app-main-wrapper">
        <Topbar
          apiConnected={apiConnected}
          socketConnected={socketConnected}
          readiness={readiness}
          onMenuClick={() => setMobileOpen(!mobileOpen)}
        />
        <main className="app-main-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
