import React from 'react';

export function DashboardCard({ title, icon: Icon, children }) {
  return (
    <div className="dashboard-card">
      <div className="card-header">
        {Icon && <Icon className="card-icon" size={20} />}
        <h3>{title}</h3>
      </div>
      <div className="card-content">
        {children}
      </div>
    </div>
  );
}
