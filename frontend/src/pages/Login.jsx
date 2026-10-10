import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Shield, Lock, User, Eye, EyeOff, AlertCircle, ArrowRight, Loader2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const destination = location.state?.from?.pathname || '/overview';

  useEffect(() => {
    if (isAuthenticated) {
      navigate(destination, { replace: true });
    }
  }, [isAuthenticated, navigate, destination]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError('Please provide both username and password.');
      return;
    }

    setLoading(true);
    setError(null);

    const result = await login(username.trim(), password);
    if (result.success) {
      navigate(destination, { replace: true });
    } else {
      setError(result.error || 'Authentication failed. Please verify your credentials.');
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: '#0b0f19',
      padding: '1.5rem',
      backgroundImage: 'radial-gradient(ellipse at 50% 20%, rgba(6, 182, 212, 0.08) 0%, transparent 60%)',
    }}>
      <div style={{
        width: '100%',
        maxWidth: '420px',
        backgroundColor: '#131b2e',
        border: '1px solid #1e293b',
        borderRadius: '12px',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5)',
        padding: '2.5rem 2rem',
      }}>
        {/* Brand Header */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '56px',
            height: '56px',
            borderRadius: '12px',
            backgroundColor: 'rgba(6, 182, 212, 0.1)',
            border: '1px solid rgba(6, 182, 212, 0.3)',
            color: '#06b6d4',
            marginBottom: '1rem',
          }}>
            <Shield size={32} />
          </div>
          <h1 style={{
            fontSize: '1.5rem',
            fontWeight: 700,
            color: '#f8fafc',
            margin: '0 0 0.35rem 0',
            letterSpacing: '-0.02em',
          }}>
            NetSentinel
          </h1>
          <p style={{
            fontSize: '0.82rem',
            color: '#94a3b8',
            margin: 0,
            lineHeight: 1.4,
          }}>
            Security Operations Console &bull; Operator Access
          </p>
        </div>

        {/* Error Alert */}
        {error && (
          <div style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.75rem',
            padding: '0.75rem 1rem',
            borderRadius: '8px',
            backgroundColor: 'rgba(239, 68, 68, 0.12)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            color: '#fca5a5',
            fontSize: '0.82rem',
            marginBottom: '1.5rem',
            lineHeight: 1.45,
          }}>
            <AlertCircle size={18} style={{ flexShrink: 0, marginTop: '1px', color: '#ef4444' }} />
            <span>{error}</span>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div>
            <label style={{
              display: 'block',
              fontSize: '0.8rem',
              fontWeight: 500,
              color: '#cbd5e1',
              marginBottom: '0.4rem',
            }}>
              Operator Username
            </label>
            <div style={{ position: 'relative' }}>
              <div style={{
                position: 'absolute',
                left: '0.85rem',
                top: '50%',
                transform: 'translateY(-50%)',
                color: '#64748b',
                display: 'flex',
                alignItems: 'center',
                pointerEvents: 'none',
              }}>
                <User size={16} />
              </div>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. admin or analyst"
                autoComplete="username"
                autoFocus
                disabled={loading}
                style={{
                  width: '100%',
                  height: '42px',
                  padding: '0 1rem 0 2.5rem',
                  backgroundColor: '#0b0f19',
                  border: '1px solid #1e293b',
                  borderRadius: '6px',
                  color: '#f8fafc',
                  fontSize: '0.875rem',
                  outline: 'none',
                  transition: 'border-color 0.2s',
                  boxSizing: 'border-box',
                }}
                onFocus={(e) => (e.target.style.borderColor = '#06b6d4')}
                onBlur={(e) => (e.target.style.borderColor = '#1e293b')}
              />
            </div>
          </div>

          <div>
            <label style={{
              display: 'block',
              fontSize: '0.8rem',
              fontWeight: 500,
              color: '#cbd5e1',
              marginBottom: '0.4rem',
            }}>
              Password
            </label>
            <div style={{ position: 'relative' }}>
              <div style={{
                position: 'absolute',
                left: '0.85rem',
                top: '50%',
                transform: 'translateY(-50%)',
                color: '#64748b',
                display: 'flex',
                alignItems: 'center',
                pointerEvents: 'none',
              }}>
                <Lock size={16} />
              </div>
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                autoComplete="current-password"
                disabled={loading}
                style={{
                  width: '100%',
                  height: '42px',
                  padding: '0 2.75rem 0 2.5rem',
                  backgroundColor: '#0b0f19',
                  border: '1px solid #1e293b',
                  borderRadius: '6px',
                  color: '#f8fafc',
                  fontSize: '0.875rem',
                  outline: 'none',
                  transition: 'border-color 0.2s',
                  boxSizing: 'border-box',
                }}
                onFocus={(e) => (e.target.style.borderColor = '#06b6d4')}
                onBlur={(e) => (e.target.style.borderColor = '#1e293b')}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                style={{
                  position: 'absolute',
                  right: '0.75rem',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  color: '#64748b',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  padding: '4px',
                }}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              width: '100%',
              height: '42px',
              marginTop: '0.5rem',
              backgroundColor: '#0284c7',
              color: '#ffffff',
              fontWeight: 600,
              fontSize: '0.875rem',
              border: 'none',
              borderRadius: '6px',
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.75 : 1,
              transition: 'background-color 0.2s',
            }}
            onMouseOver={(e) => {
              if (!loading) e.currentTarget.style.backgroundColor = '#0369a1';
            }}
            onMouseOut={(e) => {
              if (!loading) e.currentTarget.style.backgroundColor = '#0284c7';
            }}
          >
            {loading ? (
              <>
                <Loader2 size={16} className="pulse" />
                <span>Authenticating...</span>
              </>
            ) : (
              <>
                <span>Sign In to Console</span>
                <ArrowRight size={16} />
              </>
            )}
          </button>
        </form>

        {/* Security Notice Footer */}
        <div style={{
          marginTop: '2rem',
          paddingTop: '1.25rem',
          borderTop: '1px solid #1e293b',
          textAlign: 'center',
          fontSize: '0.72rem',
          color: '#64748b',
          lineHeight: 1.5,
        }}>
          Protected by NetSentinel RBAC &amp; Session Tokens.
          <br />
          Unauthorized access is strictly prohibited and audited.
        </div>
      </div>
    </div>
  );
}

export default Login;
