"""NetSentinel API Security Middleware and Controls.

Provides:
- Request correlation (X-Request-ID)
- HTTP security response headers (CSP, nosniff, frame-options)
- Bounded in-memory API rate limiting for general and sensitive operations
- Normalized API error responses without traceback leakage
- Input validation helpers
"""

from collections import deque
import logging
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

from flask import Flask, g, jsonify, request, Response
from werkzeug.exceptions import HTTPException

logger = logging.getLogger("netsentinel.security")


class InMemoryRateLimiter:
    """Thread-safe sliding-window in-memory rate limiter per client IP."""

    def __init__(
        self,
        default_limit: int = 60,
        sensitive_limit: int = 10,
        window_sec: float = 60.0,
        max_requests: Optional[int] = None,
        window_seconds: Optional[float] = None,
    ):
        if max_requests is not None:
            default_limit = max_requests
        if window_seconds is not None:
            window_sec = window_seconds

        self.default_limit = max(1, default_limit)
        self.sensitive_limit = max(1, sensitive_limit)
        self.window_sec = max(0.01, window_sec)

        self._lock = threading.Lock()
        # Keyed by (client_ip, bucket_type) -> deque of timestamps
        self._history: Dict[Tuple[str, str], deque] = {}

    def is_allowed(self, client_ip: str, is_sensitive: bool = False) -> Tuple[bool, int]:
        """Check whether a request is allowed under the rate limit window.

        Returns:
            Tuple of (is_allowed, retry_after_seconds).
        """
        now = time.time()
        bucket = "sensitive" if is_sensitive else "general"
        limit = self.sensitive_limit if is_sensitive else self.default_limit
        key = (client_ip, bucket)

        with self._lock:
            if key not in self._history:
                self._history[key] = deque()

            q = self._history[key]
            cutoff = now - self.window_sec
            while q and q[0] < cutoff:
                q.popleft()

            if len(q) >= limit:
                # Rate limit exceeded
                oldest = q[0]
                retry_after = max(1, int(oldest + self.window_sec - now))
                return False, retry_after

            q.append(now)
            return True, 0

    def check_rate_limit(self, client_ip: str, is_sensitive: bool = False) -> Tuple[bool, int, int]:
        """Check rate limit returning (allowed, remaining, retry_after)."""
        allowed, retry_after = self.is_allowed(client_ip, is_sensitive)
        limit = self.sensitive_limit if is_sensitive else self.default_limit
        with self._lock:
            q = self._history.get((client_ip, "sensitive" if is_sensitive else "general"), deque())
            remaining = max(0, limit - len(q))
        return allowed, remaining, retry_after

    def reset(self) -> None:
        """Clear all rate limit histories (for testing)."""
        with self._lock:
            self._history.clear()


class SecurityMiddleware:
    """Configures security headers, request IDs, rate limits, and normalized errors for Flask."""

    REQ_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")

    # Sensitive endpoints that alter firewall, baseline, incident state, or query external TI
    SENSITIVE_PATTERNS = [
        re.compile(r"^/api/firewall/block"),
        re.compile(r"^/api/firewall/unblock"),
        re.compile(r"^/api/fim/rebaseline"),
        re.compile(r"^/api/threat-intel/ip/[^/]+/lookup$"),
        re.compile(r"^/api/incidents/[^/]+/status$"),
    ]

    # Health endpoints immune to rate limiting to protect liveness/readiness probes
    IMMUNE_PATHS = {
        "/api/health",
        "/api/ready",
    }

    def __init__(
        self,
        app: Flask,
        rate_limit: int = 60,
        sensitive_rate_limit: int = 10,
        enable_rate_limiting: bool = True,
    ):
        self.app = app
        self.enable_rate_limiting = enable_rate_limiting
        self.rate_limiter = InMemoryRateLimiter(
            default_limit=rate_limit,
            sensitive_limit=sensitive_rate_limit,
            window_sec=60.0,
        )
        self._init_app()

    def _init_app(self) -> None:
        """Register before_request, after_request, and error handlers."""
        app = self.app

        @app.before_request
        def _before_request():
            # 1. Establish Request ID
            raw_req_id = request.headers.get("X-Request-ID", "").strip()
            if raw_req_id and self.REQ_ID_PATTERN.match(raw_req_id):
                g.request_id = raw_req_id
            else:
                g.request_id = uuid.uuid4().hex[:16]

            # 2. Rate Limiting Check (skip for immune endpoints and testing if disabled)
            if self.enable_rate_limiting and not app.config.get("TESTING", False):
                if request.path not in self.IMMUNE_PATHS and not request.path.startswith("/socket.io"):
                    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
                    if "," in client_ip:
                        client_ip = client_ip.split(",")[0].strip()

                    is_sensitive = request.method in ("POST", "PUT", "DELETE") and any(
                        p.match(request.path) for p in self.SENSITIVE_PATTERNS
                    )

                    allowed, retry_after = self.rate_limiter.is_allowed(client_ip, is_sensitive)
                    if not allowed:
                        logger.warning(
                            "Rate limit exceeded for %s on %s %s (retry_after=%ds)",
                            client_ip,
                            request.method,
                            request.path,
                            retry_after,
                        )
                        resp = jsonify({
                            "error": "rate_limited",
                            "message": f"Rate limit exceeded for {'sensitive operation' if is_sensitive else 'requests'}. Please slow down.",
                            "status_code": 429,
                            "retry_after": retry_after,
                            "request_id": g.request_id,
                        })
                        resp.status_code = 429
                        resp.headers["Retry-After"] = str(retry_after)
                        resp.headers["X-Request-ID"] = g.request_id
                        return resp

        @app.after_request
        def _after_request(response: Response):
            # 1. Inject Request ID
            req_id = getattr(g, "request_id", None)
            if req_id:
                response.headers["X-Request-ID"] = req_id

            # 2. Inject Hardened Security Headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "connect-src 'self' ws: wss: http: https:;"
            )
            return response

        # Normalize HTTP error codes
        self._register_error_handlers(app)

    def _register_error_handlers(self, app: Flask) -> None:
        """Register normalized JSON error handlers for standard HTTP error codes."""

        def _json_error(code: int, error_name: str, default_msg: str, ex: Optional[Exception] = None):
            req_id = getattr(g, "request_id", "-")
            msg = default_msg
            if ex and hasattr(ex, "description") and ex.description:
                msg = ex.description
            elif ex and str(ex) and code != 500:
                msg = str(ex)

            response = jsonify({
                "status": "error",
                "code": code,
                "error": error_name,
                "message": msg,
                "status_code": code,
                "request_id": req_id,
            })
            response.status_code = code
            if req_id != "-":
                response.headers["X-Request-ID"] = req_id
            return response

        @app.errorhandler(400)
        def bad_request(e):
            return _json_error(400, "bad_request", "Invalid request parameters.", e)

        @app.errorhandler(404)
        def not_found(e):
            return _json_error(404, "not_found", "The requested resource was not found.", e)

        @app.errorhandler(405)
        def method_not_allowed(e):
            return _json_error(405, "method_not_allowed", "HTTP method is not allowed for this route.", e)

        @app.errorhandler(409)
        def conflict(e):
            return _json_error(409, "conflict", "Resource conflict or invalid state transition.", e)

        @app.errorhandler(429)
        def too_many_requests(e):
            return _json_error(429, "rate_limited", "Rate limit exceeded. Please wait.", e)

        @app.errorhandler(503)
        def service_unavailable(e):
            return _json_error(503, "service_unavailable", "Service temporarily unavailable.", e)

        @app.errorhandler(500)
        def internal_server_error(e):
            logger.exception("Unhandled server error: %s", e)
            return _json_error(500, "internal_server_error", "An internal server error occurred.")

        @app.errorhandler(Exception)
        def unhandled_exception(e):
            if isinstance(e, HTTPException):
                return _json_error(e.code, "http_error", e.description, e)
            logger.exception("Unhandled application exception: %s", e)
            return _json_error(500, "internal_server_error", "An unexpected internal server error occurred.")
