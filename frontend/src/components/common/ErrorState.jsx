import React from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

export function ErrorState({ error, onRetry, message }) {
  let displayMessage = message;
  let isRateLimit = false;
  let isDegraded = false;

  const rawMsg = typeof error === 'string' ? error : error?.message || '';

  if (rawMsg.includes('429') || error?.status === 429 || error?.code === 429) {
    isRateLimit = true;
    displayMessage = displayMessage || 'Rate limit reached. Requests are temporarily throttled to protect system stability.';
  } else if (rawMsg.includes('503') || error?.status === 503 || error?.code === 503) {
    isDegraded = true;
    displayMessage = displayMessage || 'NetSentinel service is currently degraded or initializing.';
  } else if (rawMsg.includes('404') || error?.status === 404 || error?.code === 404) {
    displayMessage = displayMessage || 'The requested resource or entity was not found.';
  } else if (rawMsg.includes('409') || error?.status === 409 || error?.code === 409) {
    displayMessage = displayMessage || 'State conflict detected. Please refresh the view and retry.';
  } else if (rawMsg.includes('400') || error?.status === 400 || error?.code === 400) {
    displayMessage = displayMessage || error?.message || 'Invalid request parameters submitted.';
  } else if (!displayMessage) {
    displayMessage = error?.message || (typeof error === 'string' ? error : 'An unexpected error occurred while communicating with the backend.');
  }

  // Sanitize internal paths if present
  if (typeof displayMessage === 'string') {
    displayMessage = displayMessage.replace(/\/home\/[^\s:]+/g, '[redacted-path]');
  }

  const borderCol = isRateLimit
    ? 'rgba(239, 68, 68, 0.4)'
    : isDegraded
    ? 'rgba(245, 158, 11, 0.4)'
    : 'rgba(239, 68, 68, 0.3)';

  const bgCol = isRateLimit
    ? 'rgba(239, 68, 68, 0.1)'
    : isDegraded
    ? 'rgba(245, 158, 11, 0.1)'
    : 'rgba(239, 68, 68, 0.08)';

  return (
    <div
      style={{
        border: `1px solid ${borderCol}`,
        background: bgCol,
        borderRadius: '6px',
        padding: '14px 18px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        margin: '12px 0',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <AlertTriangle
          size={18}
          style={{
            color: isDegraded ? 'var(--status-yellow, #f59e0b)' : 'var(--status-red, #ef4444)',
            flexShrink: 0,
          }}
        />
        <span style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>{displayMessage}</span>
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="btn btn-secondary"
          style={{
            padding: '4px 10px',
            fontSize: '0.78rem',
            display: 'flex',
            alignItems: 'center',
            gap: '4px',
            cursor: 'pointer',
          }}
        >
          <RotateCcw size={13} />
          Retry
        </button>
      )}
    </div>
  );
}

export default ErrorState;
