import React from 'react';
import { ShieldCheck } from 'lucide-react';

export function EmptyState({ title, message = 'No data matching the current criteria.', icon: Icon = ShieldCheck, action }) {
  return (
    <div className="placeholder-state" style={{ padding: '2.5rem 1rem', textAlign: 'center' }}>
      <Icon size={32} className="placeholder-icon" style={{ opacity: 0.6, margin: '0 auto 12px auto' }} />
      {title && (
        <div style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
          {title}
        </div>
      )}
      <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', maxWidth: '400px', margin: '0 auto' }}>
        {message}
      </div>
      {action && <div style={{ marginTop: '14px' }}>{action}</div>}
    </div>
  );
}

export default EmptyState;
