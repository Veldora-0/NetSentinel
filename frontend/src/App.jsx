import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Dashboard } from './pages/Dashboard';
import { checkBackendHealth } from './services/api';
import { socket, initSocketConnection } from './services/socket';
import './App.css';

export function App() {
  const [apiStatus, setApiStatus] = useState({ connected: false, data: null });
  const [socketConnected, setSocketConnected] = useState(socket.connected);

  useEffect(() => {
    // Check initial API health and setup interval polling (every 5s)
    const fetchHealth = async () => {
      const res = await checkBackendHealth();
      setApiStatus(res);
    };

    fetchHealth();
    const interval = setInterval(fetchHealth, 5000);

    // Initialize Socket.IO connection handlers
    const cleanupSocket = initSocketConnection((connected) => {
      setSocketConnected(connected);
    });

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
        />
      </main>
    </div>
  );
}

export default App;
