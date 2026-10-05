import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Dashboard } from './pages/Dashboard';
import { checkBackendHealth, fetchTrafficMetrics, fetchSecurityAlerts, fetchMLStatus, fetchMLMetrics } from './services/api';
import { socket, initSocketConnection } from './services/socket';
import './App.css';

export function App() {
  const [apiStatus, setApiStatus] = useState({ connected: false, data: null });
  const [socketConnected, setSocketConnected] = useState(socket.connected);
  const [trafficMetrics, setTrafficMetrics] = useState(null);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [mlStatus, setMlStatus] = useState(null);
  const [mlMetrics, setMlMetrics] = useState({ window_history: [], recent_anomalies: [] });

  useEffect(() => {
    // Check initial API health, fetch metrics, alerts, and ML data
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

        const initialMLStatus = await fetchMLStatus();
        if (initialMLStatus) {
          setMlStatus(initialMLStatus);
        }

        const initialMLMetrics = await fetchMLMetrics();
        if (initialMLMetrics) {
          setMlMetrics(initialMLMetrics);
        }
      }
    };

    fetchHealthAndData();
    const interval = setInterval(fetchHealthAndData, 5000);

    // Initialize Socket.IO connection handlers, traffic metrics, security events, and ML events
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
          if (prev.some((a) => a.event_id === newAlert.event_id)) {
            return prev;
          }
          return [newAlert, ...prev].slice(0, 100);
        });
      },
      (newMLAnomaly) => {
        // Prepend new ML anomaly to recent_anomalies list
        setMlMetrics((prev) => {
          const existing = prev.recent_anomalies || [];
          if (existing.some((a) => a.event_id === newMLAnomaly.event_id)) {
            return prev;
          }
          return {
            ...prev,
            recent_anomalies: [newMLAnomaly, ...existing].slice(0, 50),
          };
        });

        // Update mlStatus latest anomaly score
        setMlStatus((prev) => prev ? {
          ...prev,
          total_anomalies_detected: (prev.total_anomalies_detected || 0) + 1,
          latest_prediction: 'ANOMALY',
          latest_anomaly_score: newMLAnomaly.anomaly_score,
          latest_raw_score: newMLAnomaly.raw_score,
        } : prev);
      },
      (statusUpdate) => {
        setMlStatus(statusUpdate);
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
          mlStatus={mlStatus}
          mlMetrics={mlMetrics}
        />
      </main>
    </div>
  );
}

export default App;
