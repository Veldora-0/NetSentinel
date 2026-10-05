import { useEffect, useRef } from 'react';
import { socket } from '../services/socket';

/**
 * Custom hook to safely subscribe to a Socket.IO event.
 * Automatically cleans up the listener on unmount to prevent memory leaks and duplicate triggers.
 *
 * @param {string} eventName - Name of the Socket.IO event.
 * @param {Function} handler - Callback invoked when the event is received.
 */
export function useSocketEvent(eventName, handler) {
  const handlerRef = useRef(handler);

  // Keep latest handler ref without re-attaching listener
  useEffect(() => {
    handlerRef.current = handler;
  }, [handler]);

  useEffect(() => {
    if (!eventName || !socket) return;

    const eventListener = (...args) => {
      if (handlerRef.current) {
        handlerRef.current(...args);
      }
    };

    socket.on(eventName, eventListener);

    return () => {
      socket.off(eventName, eventListener);
    };
  }, [eventName]);
}
