import React from 'react';
import { getWorkerStatusBadgeClass } from '../../utils/formatters';

export function StatusBadge({ status, label, text, className = '' }) {
  const displayLabel = text || label || status || 'UNKNOWN';
  const badgeClass = getWorkerStatusBadgeClass(status);

  return (
    <span className={`badge ${badgeClass} ${className}`}>
      {displayLabel}
    </span>
  );
}

export default StatusBadge;
