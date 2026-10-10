import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { loginUser, logoutUser, fetchCurrentUser } from '../services/api';

const AuthContext = createContext(null);

const TOKEN_KEY = 'token';
const TOKEN_KEY_ALT = 'netsentinel_token';
const USER_KEY = 'netsentinel_user';

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => {
    try {
      return (
        localStorage.getItem(TOKEN_KEY) ||
        localStorage.getItem(TOKEN_KEY_ALT) ||
        sessionStorage.getItem(TOKEN_KEY) ||
        null
      );
    } catch {
      return null;
    }
  });

  const [user, setUser] = useState(() => {
    try {
      const stored =
        localStorage.getItem(USER_KEY) || sessionStorage.getItem(USER_KEY);
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });

  const [loading, setLoading] = useState(true);

  const clearAuthStorage = useCallback(() => {
    try {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(TOKEN_KEY_ALT);
      localStorage.removeItem(USER_KEY);
      sessionStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem(TOKEN_KEY_ALT);
      sessionStorage.removeItem(USER_KEY);
    } catch {
      // Ignore storage errors in restricted iframe/browser environments
    }
    setToken(null);
    setUser(null);
  }, []);

  const saveAuthStorage = useCallback((authToken, authUser) => {
    try {
      localStorage.setItem(TOKEN_KEY, authToken);
      localStorage.setItem(TOKEN_KEY_ALT, authToken);
      localStorage.setItem(USER_KEY, JSON.stringify(authUser));
      // Also write to sessionStorage for compatibility
      sessionStorage.setItem(TOKEN_KEY, authToken);
      sessionStorage.setItem(USER_KEY, JSON.stringify(authUser));
    } catch {
      // Ignore storage errors
    }
    setToken(authToken);
    setUser(authUser);
  }, []);

  // Validate session on initial mount
  useEffect(() => {
    let isMounted = true;

    const verifySession = async () => {
      const existingToken =
        localStorage.getItem(TOKEN_KEY) ||
        localStorage.getItem(TOKEN_KEY_ALT) ||
        sessionStorage.getItem(TOKEN_KEY);

      if (!existingToken) {
        if (isMounted) {
          clearAuthStorage();
          setLoading(false);
        }
        return;
      }

      try {
        const response = await fetchCurrentUser();
        if (isMounted) {
          if (response?.user) {
            setUser(response.user);
            try {
              localStorage.setItem(USER_KEY, JSON.stringify(response.user));
              sessionStorage.setItem(USER_KEY, JSON.stringify(response.user));
            } catch {
              // Ignore storage errors
            }
          }
        }
      } catch (err) {
        if (isMounted) {
          if (err?.status === 401) {
            clearAuthStorage();
          }
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    verifySession();

    // Listen for global 401 events dispatched from API calls
    const handleUnauthorized = () => {
      clearAuthStorage();
    };

    window.addEventListener('auth:unauthorized', handleUnauthorized);

    return () => {
      isMounted = false;
      window.removeEventListener('auth:unauthorized', handleUnauthorized);
    };
  }, [clearAuthStorage]);

  const login = useCallback(
    async (username, password) => {
      try {
        const data = await loginUser(username, password);
        if (data?.token && data?.user) {
          saveAuthStorage(data.token, data.user);
          return { success: true, user: data.user, token: data.token };
        }
        return {
          success: false,
          error: data?.message || 'Authentication failed: No token returned.',
        };
      } catch (err) {
        return {
          success: false,
          error: err.message || 'Authentication failed.',
        };
      }
    },
    [saveAuthStorage]
  );

  const logout = useCallback(async () => {
    try {
      await logoutUser();
    } catch {
      // Ignore API logout errors and clear client session anyway
    } finally {
      clearAuthStorage();
    }
  }, [clearAuthStorage]);

  const hasRole = useCallback(
    (requiredRole) => {
      if (!user?.role) return false;
      return user.role.toUpperCase() === String(requiredRole).toUpperCase();
    },
    [user]
  );

  const hasPermission = useCallback(
    (permission) => {
      if (!user) return false;
      // Admins implicitly have all capabilities
      if (user.role?.toUpperCase() === 'ADMIN') return true;
      if (!Array.isArray(user.permissions)) return false;
      return user.permissions.includes(permission);
    },
    [user]
  );

  const value = {
    user,
    token,
    isAuthenticated: Boolean(token && user),
    loading,
    login,
    logout,
    hasRole,
    hasPermission,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
export default AuthContext;
