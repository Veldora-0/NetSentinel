/**
 * NetSentinel Socket.IO Service.
 * Manages WebSocket connection state with the Flask-SocketIO backend.
 */

import { io } from 'socket.io-client';

// Connect using relative location (Vite proxies /socket.io to http://localhost:5000)
export const socket = io({
  autoConnect: true,
  transports: ['websocket', 'polling'],
});

export function initSocketConnection(onConnectChange) {
  socket.on('connect', () => {
    if (onConnectChange) onConnectChange(true);
  });

  socket.on('disconnect', () => {
    if (onConnectChange) onConnectChange(false);
  });

  socket.on('connect_error', () => {
    if (onConnectChange) onConnectChange(false);
  });

  return () => {
    socket.off('connect');
    socket.off('disconnect');
    socket.off('connect_error');
  };
}
