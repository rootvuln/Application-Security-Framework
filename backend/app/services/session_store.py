"""In-memory, per-session result store.

The API keeps the last ``MAX_SESSION_RESULTS`` analyses per browser session so
the Session History page and ``/api/reports/{index}`` can replay them. Data is
process-local and intentionally not persisted.
"""

from __future__ import annotations

from typing import Any

from app.core.config import MAX_SESSION_RESULTS, MAX_SESSIONS

SESSION_RESULTS: dict[str, list[dict[str, Any]]] = {}


def remember(session_id: str, payload: dict[str, Any]) -> None:
    """Append a result, evicting the oldest session when the store is full."""
    if session_id not in SESSION_RESULTS and len(SESSION_RESULTS) >= MAX_SESSIONS:
        oldest = next(iter(SESSION_RESULTS))
        SESSION_RESULTS.pop(oldest, None)
    results = SESSION_RESULTS.setdefault(session_id, [])
    results.append(payload)
    del results[:-MAX_SESSION_RESULTS]


def history(session_id: str) -> list[dict[str, Any]]:
    """Return this session's results, newest first."""
    return list(reversed(SESSION_RESULTS.get(session_id, [])))


def latest(session_id: str, index: int) -> dict[str, Any] | None:
    """Return the ``index``-th newest result, or None when out of range."""
    results = history(session_id)
    if index < 0 or index >= len(results):
        return None
    return results[index]


def clear(session_id: str) -> None:
    SESSION_RESULTS.pop(session_id, None)

