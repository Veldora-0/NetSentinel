import React from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, Home, ArrowLeft } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '60vh', textAlign: 'center' }}>
      <div style={{ background: 'rgba(239, 68, 68, 0.1)', padding: '1.5rem', borderRadius: '50%', marginBottom: '1.5rem', border: '1px solid rgba(239, 68, 68, 0.25)' }}>
        <AlertTriangle size={48} color="#ef4444" />
      </div>
      <h1 style={{ fontSize: '2rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.5rem' }}>
        404 - Page Not Found
      </h1>
      <p style={{ color: '#94a3b8', maxWidth: '420px', marginBottom: '1.5rem', fontSize: '0.9rem', lineHeight: 1.5 }}>
        The requested SOC workspace route does not exist or has been relocated.
      </p>
      <Link
        to="/overview"
        className="btn-refresh"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0.5rem 1rem',
          backgroundColor: 'rgba(56, 189, 248, 0.15)',
          borderColor: '#38bdf8',
          color: '#38bdf8',
          textDecoration: 'none',
          borderRadius: '6px',
          fontWeight: 600,
        }}
      >
        <Home size={16} /> Return to SOC Overview
      </Link>
    </div>
  );
}
