"""
Retry Utilities — Configurable Retry Decorator
-------------------------------------------------
Provides a reusable retry decorator with exponential backoff for wrapping
transient-failure-prone pipeline stages (network calls, model loading, etc.).

Usage:
    from retry_utils import retry, RetryableError

    @retry(max_retries=3, backoff=1.5)
    def flaky_operation():
        ...

    # Raise RetryableError to signal that a retry is appropriate
    raise RetryableError("Transient network timeout")

This module is purely additive — nothing in the existing codebase uses it
unless you explicitly decorate a function with @retry.
"""

import time
import functools
import logging

logger = logging.getLogger(__name__)


class RetryableError(Exception):
    """Raise this to indicate a transient failure that should be retried."""
    pass


def retry(
    max_retries: int = 3,
    backoff: float = 1.5,
    initial_delay: float = 0.5,
    retryable_exceptions: tuple = (RetryableError, ConnectionError, TimeoutError, OSError),
):
    """
    Decorator that retries a function on specified exceptions.

    Args:
        max_retries: Maximum number of retry attempts (default: 3).
        backoff: Multiplier applied to delay after each retry (default: 1.5).
        initial_delay: Seconds to wait before the first retry (default: 0.5).
        retryable_exceptions: Tuple of exception types that trigger a retry.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            delay = initial_delay
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as exc:
                    last_exception = exc
                    if attempt < max_retries:
                        logger.warning(
                            f"[retry] {func.__name__} attempt {attempt + 1}/{max_retries + 1} "
                            f"failed: {exc}. Retrying in {delay:.1f}s..."
                        )
                        # Also log to pipeline_logger if available
                        try:
                            import pipeline_logger
                            pipeline_logger.log_warning(
                                f"retry_{func.__name__}",
                                f"Attempt {attempt + 1}/{max_retries + 1} failed: {exc}. "
                                f"Retrying in {delay:.1f}s...",
                                extra={"attempt": attempt + 1, "delay": delay},
                            )
                        except ImportError:
                            pass

                        time.sleep(delay)
                        delay *= backoff
                    else:
                        logger.error(
                            f"[retry] {func.__name__} exhausted all {max_retries + 1} attempts. "
                            f"Last error: {exc}"
                        )
                        try:
                            import pipeline_logger
                            pipeline_logger.log_error(
                                f"retry_{func.__name__}",
                                f"Exhausted all {max_retries + 1} attempts. Last error: {exc}",
                                extra={"total_attempts": max_retries + 1},
                            )
                        except ImportError:
                            pass

            raise last_exception  # type: ignore[misc]

        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    call_count = 0

    @retry(max_retries=3, backoff=1.0, initial_delay=0.1)
    def flaky_function():
        global call_count
        call_count += 1
        if call_count < 3:
            raise RetryableError(f"Simulated failure #{call_count}")
        return f"Success on attempt #{call_count}"

    result = flaky_function()
    print(f"Result: {result}")
    print(f"Total calls: {call_count}")
