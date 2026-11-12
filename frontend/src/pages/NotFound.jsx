import React from 'react';
import { Link } from 'react-router-dom';
import { AlertCircle, Home } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '55vh', textAlign: 'center' }}>
      <div style={{ color: '#94a3b8', marginBottom: '1rem' }}>
        <AlertCircle size={36} color="#64748b" />
      </div>
      <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.4rem' }}>
        404 - Page Not Found
      </h1>
      <p style={{ color: '#94a3b8', maxWidth: '380px', marginBottom: '1.25rem', fontSize: '0.875rem', lineHeight: 1.5 }}>
        The requested page could not be found.
      </p>
      <Link
        to="/overview"
        className="btn-refresh"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0.45rem 0.95rem',
          backgroundColor: 'rgba(56, 189, 248, 0.12)',
          borderColor: 'rgba(56, 189, 248, 0.3)',
          color: '#38bdf8',
          textDecoration: 'none',
          borderRadius: '6px',
          fontWeight: 600,
          fontSize: '0.8125rem',
        }}
      >
        <Home size={15} /> Return to Overview
      </Link>
    </div>
  );
}
