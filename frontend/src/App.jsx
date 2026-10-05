import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Dashboard } from './pages/Dashboard';
import { checkBackendHealth, fetchTrafficMetrics, fetchSecurityAlerts } from './services/api';
import { socket, initSocketConnection } from './services/socket';
import './App.css';

export function App() {
  const [apiStatus, setApiStatus] = useState({ connected: false, data: null });
  const [socketConnected, setSocketConnected] = useState(socket.connected);
  const [trafficMetrics, setTrafficMetrics] = useState(null);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    // Check initial API health, fetch metrics, and fetch recent alerts
    const fetchHealthAndData = async () => {
      const res = await checkBackendHealth();
      setApiStatus(res);
      if (res.connected) {
        if (!trafficMetrics) {
          const initialMetrics = await fetchTrafficMetrics();
          if (initialMetrics) {
            setTrafficMetrics(initialMetrics);
          }
        }
        const initialAlerts = await fetchSecurityAlerts(50);
        if (initialAlerts && initialAlerts.length > 0) {
          setAlerts(initialAlerts);
        }
      }
    };

    fetchHealthAndData();
    const interval = setInterval(fetchHealthAndData, 5000);

    // Initialize Socket.IO connection handlers, traffic metrics, and security events
    const cleanupSocket = initSocketConnection(
      (connected) => {
        setSocketConnected(connected);
      },
      (metrics) => {
        setTrafficMetrics(metrics);

        // Append to rolling chart history (max 20 points)
        const nowStr = new Date(metrics.timestamp * 1000).toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        });

        setTrafficHistory((prev) => {
          const updated = [
            ...prev,
            {
              time: nowStr,
              pps: metrics.packets_per_sec,
              bps: metrics.bytes_per_sec,
            },
          ];
          return updated.slice(-20);
        });
      },
      (newAlert) => {
        // Prepend new security alert to list (keep latest 100)
        setAlerts((prev) => {
          // Avoid duplicate event_id if already present
          if (prev.some((a) => a.event_id === newAlert.event_id)) {
            return prev;
          }
          return [newAlert, ...prev].slice(0, 100);
        });
      }
    );

    return () => {
      clearInterval(interval);
      cleanupSocket();
    };
  }, []);

  return (
    <div className="app-container">
      <Header 
        apiConnected={apiStatus.connected} 
        socketConnected={socketConnected} 
      />
      <main className="main-content">
        <Dashboard 
          apiStatus={apiStatus} 
          socketConnected={socketConnected}
          trafficMetrics={trafficMetrics}
          trafficHistory={trafficHistory}
          alerts={alerts}
        />
      </main>
    </div>
  );
}

export default App;
