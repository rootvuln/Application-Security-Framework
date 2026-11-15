"""Application-wide constants.

Limits live here so that the API layer, the analyzers and the frontend contract
cannot drift apart: a single change to ``MAX_FILE_SIZE`` propagates everywhere.
"""

from __future__ import annotations

SERVICE_NAME = "CyberSuite API"
SERVICE_VERSION = "0.1.0"

# Upload limits (bytes)
MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_LOG_SIZE = 10 * 1024 * 1024

# Session history
MAX_SESSION_RESULTS = 100
MAX_SESSIONS = 1000
SESSION_COOKIE = "cybersuite_session"

# Rate limiting
RATE_LIMIT_REQUESTS = 60
RATE_LIMIT_WINDOW_SECONDS = 60.0
RATE_LIMIT_EXEMPT_PATHS = frozenset(
    {"/api/health", "/docs", "/openapi.json", "/redoc"}
)

# CORS
ALLOWED_ORIGINS = (
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
)

