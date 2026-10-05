import React from 'react';

export function MetricCard({ title, value, subtext, icon: Icon, badge, badgeClass = '', className = '', onClick }) {
  return (
    <div
      className={`dashboard-card metric-card ${onClick ? 'clickable' : ''} ${className}`}
      onClick={onClick}
      style={onClick ? { cursor: 'pointer' } : undefined}
    >
      <div className="card-header" style={{ justifyContent: 'space-between', marginBottom: '8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {Icon && <Icon size={18} className="card-icon" />}
          <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: 500 }}>
            {title}
          </span>
        </div>
        {badge && (
          React.isValidElement(badge) ? (
            badge
          ) : (
            <span className={`badge ${badgeClass}`}>{badge}</span>
          )
        )}
      </div>
      <div className="metric-value-container">
        <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.2 }}>
          {value !== null && value !== undefined && value !== '' ? value : '—'}
        </div>
        {subtext && (
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            {subtext}
          </div>
        )}
      </div>
    </div>
  );
}

export default MetricCard;
