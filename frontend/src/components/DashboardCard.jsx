import React from 'react';

export function DashboardCard({
  title,
  subtitle,
  icon: Icon,
  action,
  headerRight,
  className = '',
  style,
  children,
}) {
  const rightSlot = action || headerRight;

  return (
    <div className={`dashboard-card ${className}`} style={style}>
      <div className="card-header">
        <div className="card-header-left">
          {Icon && <Icon className="card-icon" size={17} />}
          <div className="card-header-titles">
            <h3 className="card-title">{title}</h3>
            {subtitle && <span className="card-subtitle">{subtitle}</span>}
          </div>
        </div>
        {rightSlot && <div className="card-header-right">{rightSlot}</div>}
      </div>
      <div className="card-content">{children}</div>
    </div>
  );
}

export default DashboardCard;
