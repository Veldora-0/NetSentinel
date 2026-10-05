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

export default socket;
