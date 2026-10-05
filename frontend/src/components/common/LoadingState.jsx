import React from 'react';
import { Activity } from 'lucide-react';

export function LoadingState({ message = 'Loading data...', compact = false }) {
  if (compact) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '12px', color: 'var(--text-secondary)' }}>
        <Activity size={16} className="pulse" style={{ color: 'var(--accent-cyan)' }} />
        <span style={{ fontSize: '0.85rem' }}>{message}</span>
      </div>
    );
  }

  return (
    <div className="placeholder-state" style={{ padding: '3rem 1rem' }}>
      <Activity size={32} className="placeholder-icon pulse" style={{ color: 'var(--accent-cyan)' }} />
      <div style={{ marginTop: '12px', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
        {message}
      </div>
    </div>
  );
}
