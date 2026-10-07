import React from 'react';

export function MetricCard({
  title,
  value,
  subtext,
  icon: Icon,
  badge,
  badgeClass = '',
  className = '',
  onClick,
}) {
  return (
    <div
      className={`dashboard-card metric-card ${onClick ? 'clickable' : ''} ${className}`}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (e) => e.key === 'Enter' && onClick() : undefined}
    >
      <div className="metric-card-top">
        <div className="metric-title-group">
          {Icon && (
            <div className="metric-icon-wrapper">
              <Icon size={16} className="metric-card-icon" />
            </div>
          )}
          <span className="metric-title">{title}</span>
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
        <div className="metric-value">
          {value !== null && value !== undefined && value !== '' ? value : '—'}
        </div>
        {subtext && <div className="metric-subtext">{subtext}</div>}
      </div>
    </div>
  );
}

export default MetricCard;
