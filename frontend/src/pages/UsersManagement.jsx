import React, { useState, useEffect, useCallback } from 'react';
import {
  Users,
  UserPlus,
  Shield,
  KeyRound,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  UserCheck,
  UserX,
} from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { DashboardCard } from '../components/DashboardCard';
import { LoadingState } from '../components/common/LoadingState';
import { ErrorState } from '../components/common/ErrorState';
import { fetchUsers, createUser, updateUser, deleteUser } from '../services/api';
import { useAuth } from '../context/AuthContext';

export default function UsersManagement() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [feedback, setFeedback] = useState(null);

  // Form states for creating a user
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('VIEWER');
  const [createLoading, setCreateLoading] = useState(false);

  // Modal / action state for updating password
  const [resetTargetId, setResetTargetId] = useState(null);
  const [resetPasswordVal, setResetPasswordVal] = useState('');

  const loadUsers = useCallback(async () => {
    try {
      setError(null);
      const data = await fetchUsers();
      if (data && data.users) {
        setUsers(data.users);
      }
    } catch (err) {
      setError(err.message || 'Failed to load user records');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    if (!newUsername.trim() || !newPassword.trim()) return;

    setCreateLoading(true);
    setFeedback(null);
    try {
      await createUser({
        username: newUsername.trim(),
        password: newPassword.trim(),
        role: newRole,
      });
      setFeedback({ type: 'success', text: `User '${newUsername.trim()}' created successfully.` });
      setNewUsername('');
      setNewPassword('');
      setNewRole('VIEWER');
      await loadUsers();
    } catch (err) {
      setFeedback({ type: 'error', text: err.message || 'Failed to create user.' });
    } finally {
      setCreateLoading(false);
    }
  };

  const handleToggleStatus = async (user) => {
    setFeedback(null);
    try {
      await updateUser(user.id, { is_active: !user.is_active });
      setFeedback({
        type: 'success',
        text: `User '${user.username}' ${user.is_active ? 'deactivated' : 'activated'}.`,
      });
      await loadUsers();
    } catch (err) {
      setFeedback({ type: 'error', text: err.message || 'Failed to update user status.' });
    }
  };

  const handleRoleChange = async (user, nextRole) => {
    if (user.role === nextRole) return;
    setFeedback(null);
    try {
      await updateUser(user.id, { role: nextRole });
      setFeedback({ type: 'success', text: `User '${user.username}' role updated to ${nextRole}.` });
      await loadUsers();
    } catch (err) {
      setFeedback({ type: 'error', text: err.message || 'Failed to update role.' });
    }
  };

  const handleResetPassword = async (userId) => {
    if (!resetPasswordVal.trim()) return;
    setFeedback(null);
    try {
      await updateUser(userId, { password: resetPasswordVal.trim() });
      setFeedback({ type: 'success', text: 'Password reset successfully.' });
      setResetTargetId(null);
      setResetPasswordVal('');
    } catch (err) {
      setFeedback({ type: 'error', text: err.message || 'Failed to reset password.' });
    }
  };

  const handleDeleteUser = async (user) => {
    if (!window.confirm(`Are you sure you want to permanently delete user '${user.username}'?`)) {
      return;
    }
    setFeedback(null);
    try {
      await deleteUser(user.id);
      setFeedback({ type: 'success', text: `User '${user.username}' deleted successfully.` });
      await loadUsers();
    } catch (err) {
      setFeedback({ type: 'error', text: err.message || 'Failed to delete user.' });
    }
  };

  if (loading && users.length === 0) {
    return <LoadingState message="Loading authorized operators and users..." />;
  }

  if (error && users.length === 0) {
    return <ErrorState error={error} onRetry={loadUsers} />;
  }

  return (
    <div className="page-container">
      <PageHeader
        title="User & Access Management"
        subtitle="Manage NetSentinel operator accounts, role boundaries, and credentials"
        actions={
          <button className="btn-refresh" onClick={loadUsers} title="Refresh User List">
            <RotateCcw size={14} /> Refresh
          </button>
        }
      />

      {feedback && (
        <div
          style={{
            padding: '10px 14px',
            borderRadius: '6px',
            marginBottom: '1.25rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            fontSize: '0.875rem',
            background: feedback.type === 'success' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(239, 68, 68, 0.15)',
            border: feedback.type === 'success' ? '1px solid #22c55e' : '1px solid #ef4444',
            color: feedback.type === 'success' ? '#86efac' : '#fca5a5',
          }}
        >
          {feedback.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
          <span>{feedback.text}</span>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 2fr) minmax(0, 1fr)', gap: '1.5rem', alignItems: 'start' }}>
        {/* User Directory */}
        <DashboardCard title={`Active Operators & Accounts (${users.length})`} icon={Users}>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-color, #1e293b)', textAlign: 'left', color: '#94a3b8' }}>
                  <th style={{ padding: '8px 12px' }}>Username</th>
                  <th style={{ padding: '8px 12px' }}>Role</th>
                  <th style={{ padding: '8px 12px' }}>Status</th>
                  <th style={{ padding: '8px 12px' }}>Permissions</th>
                  <th style={{ padding: '8px 12px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const isSelf = currentUser && currentUser.id === u.id;
                  return (
                    <tr key={u.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                      <td style={{ padding: '10px 12px', fontWeight: 600, color: '#f8fafc' }}>
                        {u.username}
                        {isSelf && <span style={{ marginLeft: '6px', fontSize: '0.7rem', color: '#38bdf8' }}>(You)</span>}
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        <select
                          value={u.role}
                          onChange={(e) => handleRoleChange(u, e.target.value)}
                          disabled={isSelf}
                          style={{
                            background: 'var(--bg-dark, #0b0f19)',
                            color: '#f8fafc',
                            border: '1px solid var(--border-color, #1e293b)',
                            borderRadius: '4px',
                            padding: '4px 8px',
                            fontSize: '0.8rem',
                          }}
                        >
                          <option value="VIEWER">VIEWER</option>
                          <option value="ANALYST">ANALYST</option>
                          <option value="ADMIN">ADMIN</option>
                        </select>
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        <span
                          style={{
                            display: 'inline-block',
                            padding: '2px 8px',
                            borderRadius: '9999px',
                            fontSize: '0.75rem',
                            fontWeight: 600,
                            background: u.is_active ? 'rgba(34, 197, 94, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                            color: u.is_active ? '#4ade80' : '#f87171',
                          }}
                        >
                          {u.is_active ? 'ACTIVE' : 'DISABLED'}
                        </span>
                      </td>
                      <td style={{ padding: '10px 12px', color: '#94a3b8', fontSize: '0.75rem' }}>
                        {Array.isArray(u.permissions) ? u.permissions.length : 0} scope(s)
                      </td>
                      <td style={{ padding: '10px 12px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: '6px', justifyContent: 'flex-end' }}>
                          <button
                            onClick={() => handleToggleStatus(u)}
                            disabled={isSelf}
                            title={u.is_active ? 'Deactivate user' : 'Activate user'}
                            style={{
                              background: 'transparent',
                              border: '1px solid var(--border-color, #1e293b)',
                              color: u.is_active ? '#f87171' : '#4ade80',
                              borderRadius: '4px',
                              padding: '4px 6px',
                              cursor: isSelf ? 'not-allowed' : 'pointer',
                              opacity: isSelf ? 0.4 : 1,
                            }}
                          >
                            {u.is_active ? <UserX size={14} /> : <UserCheck size={14} />}
                          </button>
                          <button
                            onClick={() => setResetTargetId(resetTargetId === u.id ? null : u.id)}
                            title="Reset Password"
                            style={{
                              background: 'transparent',
                              border: '1px solid var(--border-color, #1e293b)',
                              color: '#38bdf8',
                              borderRadius: '4px',
                              padding: '4px 6px',
                              cursor: 'pointer',
                            }}
                          >
                            <KeyRound size={14} />
                          </button>
                          <button
                            onClick={() => handleDeleteUser(u)}
                            disabled={isSelf}
                            title="Delete user"
                            style={{
                              background: 'transparent',
                              border: '1px solid var(--border-color, #1e293b)',
                              color: '#ef4444',
                              borderRadius: '4px',
                              padding: '4px 6px',
                              cursor: isSelf ? 'not-allowed' : 'pointer',
                              opacity: isSelf ? 0.4 : 1,
                            }}
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                        {resetTargetId === u.id && (
                          <div style={{ marginTop: '8px', display: 'flex', gap: '6px', justifyContent: 'flex-end' }}>
                            <input
                              type="password"
                              placeholder="New password (min 8 chars)"
                              value={resetPasswordVal}
                              onChange={(e) => setResetPasswordVal(e.target.value)}
                              style={{
                                background: 'var(--bg-dark, #0b0f19)',
                                color: '#fff',
                                border: '1px solid #38bdf8',
                                borderRadius: '4px',
                                padding: '4px 8px',
                                fontSize: '0.75rem',
                                width: '180px',
                              }}
                            />
                            <button
                              onClick={() => handleResetPassword(u.id)}
                              style={{
                                background: '#0284c7',
                                color: '#fff',
                                border: 'none',
                                borderRadius: '4px',
                                padding: '4px 8px',
                                fontSize: '0.75rem',
                                cursor: 'pointer',
                              }}
                            >
                              Save
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </DashboardCard>

        {/* Create User Form */}
        <DashboardCard title="Provision Operator" icon={UserPlus}>
          <form onSubmit={handleCreateUser} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: '#94a3b8', marginBottom: '4px' }}>
                Username
              </label>
              <input
                type="text"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                placeholder="e.g., sec_analyst_1"
                required
                style={{
                  width: '100%',
                  background: 'var(--bg-dark, #0b0f19)',
                  border: '1px solid var(--border-color, #1e293b)',
                  borderRadius: '6px',
                  padding: '8px 12px',
                  color: '#fff',
                  fontSize: '0.85rem',
                }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: '#94a3b8', marginBottom: '4px' }}>
                Password (min 8 characters)
              </label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                style={{
                  width: '100%',
                  background: 'var(--bg-dark, #0b0f19)',
                  border: '1px solid var(--border-color, #1e293b)',
                  borderRadius: '6px',
                  padding: '8px 12px',
                  color: '#fff',
                  fontSize: '0.85rem',
                }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: '#94a3b8', marginBottom: '4px' }}>
                Role
              </label>
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value)}
                style={{
                  width: '100%',
                  background: 'var(--bg-dark, #0b0f19)',
                  border: '1px solid var(--border-color, #1e293b)',
                  borderRadius: '6px',
                  padding: '8px 12px',
                  color: '#fff',
                  fontSize: '0.85rem',
                }}
              >
                <option value="VIEWER">VIEWER (Read-Only SOC)</option>
                <option value="ANALYST">ANALYST (Incidents & Threat Intel)</option>
                <option value="ADMIN">ADMIN (Full Security Management)</option>
              </select>
            </div>
            <button
              type="submit"
              disabled={createLoading}
              style={{
                background: '#0284c7',
                color: '#fff',
                border: 'none',
                borderRadius: '6px',
                padding: '10px 14px',
                fontWeight: 600,
                fontSize: '0.85rem',
                cursor: createLoading ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem',
                marginTop: '0.5rem',
              }}
            >
              <UserPlus size={16} />
              {createLoading ? 'Creating...' : 'Create Account'}
            </button>
          </form>
        </DashboardCard>
      </div>
    </div>
  );
}
