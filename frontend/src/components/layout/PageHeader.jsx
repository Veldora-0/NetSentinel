import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';

export function PageHeader({ title, subtitle, backLink, backLabel = 'Back', actions }) {
  return (
    <div className="page-header">
      <div className="page-header-title-area">
        {backLink && (
          <Link to={backLink} className="page-back-link" title={backLabel}>
            <ArrowLeft size={16} />
            <span>{backLabel}</span>
          </Link>
        )}
        <h1 className="page-title">{title}</h1>
        {subtitle && <p className="page-subtitle">{subtitle}</p>}
      </div>
      {actions && <div className="page-header-actions">{actions}</div>}
    </div>
  );
}
