import React from 'react';
import { getSeverityBadgeClass } from '../../utils/formatters';

export function SeverityBadge({ severity, className = '' }) {
  const safeSeverity = (severity || 'LOW').toUpperCase();
  const badgeClass = getSeverityBadgeClass(safeSeverity);

  return (
    <span className={`badge ${badgeClass} ${className}`}>
      {safeSeverity}
    </span>
  );
}
