import React from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { LoadingState } from '../common/LoadingState';
import { ShieldAlert } from 'lucide-react';

export function ProtectedRoute({ requiredRole, requiredPermission, children }) {
  const { isAuthenticated, loading, user, hasRole, hasPermission } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '100vh',
        backgroundColor: 'var(--bg-dark, #0b0f19)',
      }}>
        <LoadingState message="Verifying security credentials..." />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  if (requiredRole && !hasRole(requiredRole)) {
    return (
      <div className="page-container" style={{ padding: '3rem 1rem', textAlign: 'center' }}>
        <div style={{
          maxWidth: '500px',
          margin: '0 auto',
          background: 'var(--bg-card, #131b2e)',
          border: '1px solid var(--border-color, #1e293b)',
          borderRadius: '8px',
          padding: '2rem',
        }}>
          <ShieldAlert size={48} style={{ color: 'var(--status-red, #ef4444)', margin: '0 auto 1rem' }} />
          <h2 style={{ fontSize: '1.25rem', color: '#f8fafc', marginBottom: '0.5rem' }}>Access Denied</h2>
          <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginBottom: '1.5rem' }}>
            This section requires the <strong>{requiredRole}</strong> role. Your current role is <strong>{user?.role}</strong>.
          </p>
        </div>
      </div>
    );
  }

  if (requiredPermission && !hasPermission(requiredPermission)) {
    return (
      <div className="page-container" style={{ padding: '3rem 1rem', textAlign: 'center' }}>
        <div style={{
          maxWidth: '500px',
          margin: '0 auto',
          background: 'var(--bg-card, #131b2e)',
          border: '1px solid var(--border-color, #1e293b)',
          borderRadius: '8px',
          padding: '2rem',
        }}>
          <ShieldAlert size={48} style={{ color: 'var(--status-red, #ef4444)', margin: '0 auto 1rem' }} />
          <h2 style={{ fontSize: '1.25rem', color: '#f8fafc', marginBottom: '0.5rem' }}>Insufficient Privileges</h2>
          <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginBottom: '1.5rem' }}>
            This operation requires <code>{requiredPermission}</code> permission.
          </p>
        </div>
      </div>
    );
  }

  return children ? children : <Outlet />;
}

export default ProtectedRoute;
