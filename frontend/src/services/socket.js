/**
 * NetSentinel Socket.IO Service.
 * Manages WebSocket connection state with the Flask-SocketIO backend.
 * Provides authenticated connection handshakes and dynamic auth token updates.
 */

import { io } from 'socket.io-client';

const getToken = () => {
  try {
    return (
      localStorage.getItem('token') ||
      localStorage.getItem('netsentinel_token') ||
      sessionStorage.getItem('token') ||
      ''
    );
  } catch {
    return '';
  }
};

const initialToken = getToken();

// Connect using relative location (Vite proxies /socket.io to http://localhost:5000)
// autoConnect is only enabled if an active token is already present in browser storage
export const socket = io({
  autoConnect: Boolean(initialToken),
  reconnection: true,
  reconnectionAttempts: 5,
  reconnectionDelay: 1000,
  reconnectionDelayMax: 5000,
  timeout: 20000,
  transports: ['websocket', 'polling'],
  auth: (cb) => {
    cb({ token: getToken() });
  },
});

// Immediately disconnect and halt reconnection if connection fails due to invalid/missing credentials
socket.on('connect_error', (err) => {
  const currentToken = getToken();
  const errMsg = (err?.message || '').toLowerCase();
  if (
    !currentToken ||
    errMsg.includes('unauthenticated') ||
    errMsg.includes('unauthorized') ||
    errMsg.includes('insufficient permissions') ||
    errMsg.includes('refused')
  ) {
    socket.disconnect();
  }
});

// Helper to reconnect with updated credentials upon login or disconnect on logout
export const updateSocketAuth = (token) => {
  if (socket) {
    const activeToken = token || getToken();
    socket.auth = { token: activeToken };
    if (activeToken) {
      if (socket.connected) {
        socket.disconnect().connect();
      } else {
        socket.connect();
      }
    } else {
      if (socket.connected) {
        socket.disconnect();
      }
    }
  }
};

// Reconnect/disconnect listener for global authentication events
if (typeof window !== 'undefined') {
  window.addEventListener('auth:unauthorized', () => {
    if (socket && socket.connected) {
      socket.disconnect();
    }
  });
}

export default socket;
