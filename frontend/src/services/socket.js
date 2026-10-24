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

// Connect using relative location (Vite proxies /socket.io to http://localhost:5000)
export const socket = io({
  autoConnect: true,
  reconnection: true,
  reconnectionAttempts: Infinity,
  reconnectionDelay: 1000,
  reconnectionDelayMax: 5000,
  timeout: 20000,
  transports: ['websocket', 'polling'],
  auth: (cb) => {
    cb({ token: getToken() });
  },
});

// Helper to reconnect with updated credentials upon login
export const updateSocketAuth = (token) => {
  if (socket) {
    socket.auth = { token: token || getToken() };
    if (socket.connected) {
      socket.disconnect().connect();
    } else {
      socket.connect();
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
