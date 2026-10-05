import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppLayout } from './components/layout/AppLayout';
import Overview from './pages/Overview';
import Network from './pages/Network';
import Detection from './pages/Detection';
import HostSecurity from './pages/HostSecurity';
import Incidents from './pages/Incidents';
import IncidentDetail from './pages/IncidentDetail';
import ThreatIntelligence from './pages/ThreatIntelligence';
import Firewall from './pages/Firewall';
import History from './pages/History';
import System from './pages/System';
import NotFound from './pages/NotFound';
import './App.css';

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppLayout />}>
          <Route path="/" element={<Navigate to="/overview" replace />} />
          <Route path="/overview" element={<Overview />} />
          <Route path="/network" element={<Network />} />
          <Route path="/detection" element={<Detection />} />
          <Route path="/host" element={<HostSecurity />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/incidents/:incidentId" element={<IncidentDetail />} />
          <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
          <Route path="/firewall" element={<Firewall />} />
          <Route path="/history" element={<History />} />
          <Route path="/system" element={<System />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
