import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Dashboard } from './pages/Dashboard';
import { checkBackendHealth, fetchTrafficMetrics } from './services/api';
import { socket, initSocketConnection } from './services/socket';
import './App.css';

export function App() {
  const [apiStatus, setApiStatus] = useState({ connected: false, data: null });
  const [socketConnected, setSocketConnected] = useState(socket.connected);
  const [trafficMetrics, setTrafficMetrics] = useState(null);
  const [trafficHistory, setTrafficHistory] = useState([]);

  useEffect(() => {
    // Check initial API health and setup interval polling (every 5s)
    const fetchHealth = async () => {
      const res = await checkBackendHealth();
      setApiStatus(res);
      if (res.connected && !trafficMetrics) {
        const initialMetrics = await fetchTrafficMetrics();
        if (initialMetrics) {
          setTrafficMetrics(initialMetrics);
        }
      }
    };

    fetchHealth();
    const interval = setInterval(fetchHealth, 5000);

    // Initialize Socket.IO connection handlers and real-time traffic metrics
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
        />
      </main>
    </div>
  );
}

export default App;
