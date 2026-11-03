from pathlib import Path
import sys
from collections import defaultdict, deque
import secrets
import logging
from time import monotonic

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import uvicorn
from app.api.routes import router

app = FastAPI(
    title="CyberSuite API",
    description="Cybersecurity analysis backend",
    version="0.1.0",
)
audit_logger = logging.getLogger("cybersuite.audit")

app.include_router(router)

_request_times: defaultdict[str, deque[float]] = defaultdict(deque)
_RATE_LIMIT = 60
_RATE_WINDOW_SECONDS = 60.0


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS" or request.url.path in {"/api/health", "/docs", "/openapi.json", "/redoc"}:
            return await call_next(request)
        client = request.client.host if request.client else "unknown"
        now = monotonic()
        timestamps = _request_times[client]
        while timestamps and now - timestamps[0] >= _RATE_WINDOW_SECONDS:
            timestamps.popleft()
        if not timestamps and client in _request_times:
            _request_times.pop(client, None)
            timestamps = _request_times[client]
        if len(timestamps) >= _RATE_LIMIT:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded; try again later"},
                headers={"Retry-After": "60"},
            )
        timestamps.append(now)
        session_id = request.cookies.get("cybersuite_session")
        if not session_id:
            session_id = secrets.token_urlsafe(24)
        request.state.session_id = session_id
        response = await call_next(request)
        audit_logger.info(
            "request method=%s path=%s status=%s client=%s",
            request.method,
            request.url.path,
            response.status_code,
            client,
        )
        if "cybersuite_session" not in request.cookies:
            response.set_cookie(
                "cybersuite_session",
                session_id,
                httponly=True,
                samesite="lax",
                secure=False,
                max_age=86400,
            )
        return response


# Rate limit middleware is inner; CORSMiddleware is outer so preflight and 429 carry CORS headers
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health_check():
    return {
        "success": True,
        "status": "running",
        "service": "CyberSuite API",
    }


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
