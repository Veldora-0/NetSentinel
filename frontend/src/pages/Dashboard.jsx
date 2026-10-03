import React from 'react';
import { 
  Server, 
  AlertTriangle, 
  Activity, 
  ShieldAlert, 
  Cpu, 
  BarChart2 
} from 'lucide-react';
import { DashboardCard } from '../components/DashboardCard';

export function Dashboard({ apiStatus, socketConnected }) {
  return (
    <div className="dashboard-container">
      <div className="dashboard-grid">
        {/* 1. System Status */}
        <DashboardCard title="System Status" icon={Server}>
          <div className="status-detail-list">
            <div className="detail-item">
              <span className="detail-label">Backend Service:</span>
              <span className={`badge ${apiStatus.connected ? 'badge-success' : 'badge-danger'}`}>
                {apiStatus.connected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Service Name:</span>
              <span className="detail-value">{apiStatus.data?.service || 'N/A'}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Socket.IO Stream:</span>
              <span className={`badge ${socketConnected ? 'badge-success' : 'badge-danger'}`}>
                {socketConnected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
          </div>
        </DashboardCard>

        {/* 2. Live Security Alerts */}
        <DashboardCard title="Live Security Alerts" icon={AlertTriangle}>
          <div className="placeholder-state">
            <ShieldAlert size={36} className="placeholder-icon" />
            <p className="placeholder-text">No active alerts</p>
          </div>
        </DashboardCard>

        {/* 3. Network Traffic */}
        <DashboardCard title="Network Traffic" icon={Activity}>
          <div className="placeholder-state">
            <Activity size={36} className="placeholder-icon pulse" />
            <p className="placeholder-text">Waiting for network traffic telemetry</p>
          </div>
        </DashboardCard>

        {/* 4. Blocked IPs */}
        <DashboardCard title="Blocked IPs" icon={ShieldAlert}>
          <div className="placeholder-state">
            <p className="placeholder-text">No blocked IPs</p>
          </div>
        </DashboardCard>

        {/* 5. System Resources */}
        <DashboardCard title="System Resources" icon={Cpu}>
          <div className="placeholder-state">
            <Cpu size={36} className="placeholder-icon" />
            <p className="placeholder-text">Waiting for telemetry</p>
          </div>
        </DashboardCard>

        {/* 6. Detection Statistics */}
        <DashboardCard title="Detection Statistics" icon={BarChart2}>
          <div className="placeholder-state">
            <BarChart2 size={36} className="placeholder-icon" />
            <p className="placeholder-text">Waiting for detection engine</p>
          </div>
        </DashboardCard>
      </div>
    </div>
  );
}
