"""
Pipeline Logger — Structured Logging & Monitoring
----------------------------------------------------
Provides structured, timestamped JSON logging for every stage of the
ComplianceMesh pipeline (ingestion, retrieval, generation, agent calls).

Usage:
    import pipeline_logger as plog

    # Log a pipeline stage
    plog.log_stage("agent1_ingestion", "Extracted 42 controls from HIPAA PDF",
                   extra={"controls_count": 42, "file": "hipaa.pdf"})

    # Time a function automatically
    @plog.timed("rag_retrieval")
    def retrieve(...):
        ...

    # Get recent logs for the Streamlit UI
    recent = plog.get_recent_logs(n=20)

Log output goes to:
    logs/pipeline.jsonl   (append-only, one JSON object per line)

This module is purely additive — nothing in the existing codebase imports
it unless you explicitly add a call.
"""

import os
import json
import time
import functools
import threading
from datetime import datetime, timezone
from collections import deque

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LOGS_DIR = "logs"
LOG_FILE = os.path.join(LOGS_DIR, "pipeline.jsonl")
_RING_BUFFER_SIZE = 200  # max recent entries kept in memory for UI display

# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_ring_buffer: deque = deque(maxlen=_RING_BUFFER_SIZE)
_initialized = False


def _ensure_dir():
    global _initialized
    if not _initialized:
        os.makedirs(LOGS_DIR, exist_ok=True)
        _initialized = True


# ---------------------------------------------------------------------------
# Core logging
# ---------------------------------------------------------------------------
def log_stage(
    stage: str,
    message: str,
    level: str = "INFO",
    extra: dict | None = None,
    duration_seconds: float | None = None,
):
    """
    Write a structured log entry for a pipeline stage.

    Args:
        stage: Identifier like "agent1_ingestion", "rag_retrieval", etc.
        message: Human-readable description of what happened.
        level: One of "INFO", "WARNING", "ERROR".
        extra: Optional dict of additional key-value pairs (metrics, counts, etc.).
        duration_seconds: Optional elapsed time for this stage.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "stage": stage,
        "message": message,
    }
    if duration_seconds is not None:
        entry["duration_seconds"] = round(duration_seconds, 4)
    if extra:
        entry["extra"] = extra

    with _lock:
        _ring_buffer.append(entry)
        _ensure_dir()
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass  # non-critical — don't crash the pipeline for a log write failure


def log_info(stage: str, message: str, **kwargs):
    """Convenience wrapper: log at INFO level."""
    log_stage(stage, message, level="INFO", **kwargs)


def log_warning(stage: str, message: str, **kwargs):
    """Convenience wrapper: log at WARNING level."""
    log_stage(stage, message, level="WARNING", **kwargs)


def log_error(stage: str, message: str, **kwargs):
    """Convenience wrapper: log at ERROR level."""
    log_stage(stage, message, level="ERROR", **kwargs)


# ---------------------------------------------------------------------------
# Timing decorator
# ---------------------------------------------------------------------------
def timed(stage_name: str):
    """
    Decorator that logs the execution time of a function.

    Usage:
        @timed("rag_retrieval")
        def retrieve(query, ...):
            ...
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            t0 = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                elapsed = time.perf_counter() - t0
                log_info(
                    stage_name,
                    f"{func.__name__} completed in {elapsed:.3f}s",
                    duration_seconds=elapsed,
                )
                return result
            except Exception as exc:
                elapsed = time.perf_counter() - t0
                log_error(
                    stage_name,
                    f"{func.__name__} failed after {elapsed:.3f}s: {exc}",
                    duration_seconds=elapsed,
                    extra={"error": str(exc)},
                )
                raise
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Query interface (for the Streamlit UI)
# ---------------------------------------------------------------------------
def _load_from_disk_if_empty():
    """Populates ring buffer from disk log file if empty."""
    with _lock:
        if not _ring_buffer and os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    for line in lines[-_RING_BUFFER_SIZE:]:
                        if line.strip():
                            _ring_buffer.append(json.loads(line))
            except Exception:
                pass

def get_recent_logs(n: int = 50) -> list[dict]:
    """Returns the N most recent log entries."""
    _load_from_disk_if_empty()
    with _lock:
        entries = list(_ring_buffer)
    return entries[-n:]


def get_stage_summary() -> dict:
    """
    Returns a summary of all logged stages:
    {stage_name: {"count": int, "total_duration": float, "errors": int}}
    """
    _load_from_disk_if_empty()
    summary: dict[str, dict] = {}
    with _lock:
        entries = list(_ring_buffer)
    for entry in entries:
        stage = entry["stage"]
        if stage not in summary:
            summary[stage] = {"count": 0, "total_duration": 0.0, "errors": 0}
        summary[stage]["count"] += 1
        summary[stage]["total_duration"] += entry.get("duration_seconds", 0.0)
        if entry.get("level") == "ERROR":
            summary[stage]["errors"] += 1
    return summary


def clear_logs():
    """Clears the in-memory ring buffer (does not delete the log file)."""
    with _lock:
        _ring_buffer.clear()


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    log_info("test", "Pipeline logger module loaded successfully.")
    log_warning("test", "This is a test warning.", extra={"detail": "just testing"})

    @timed("test_function")
    def slow_function():
        time.sleep(0.1)
        return 42

    result = slow_function()
    print(f"Function returned: {result}")
    print(f"\nRecent logs ({len(get_recent_logs())} entries):")
    for entry in get_recent_logs():
        print(f"  [{entry['level']}] {entry['stage']}: {entry['message']}")
    print(f"\nStage summary: {json.dumps(get_stage_summary(), indent=2)}")
    print(f"\nLog file: {os.path.abspath(LOG_FILE)}")
