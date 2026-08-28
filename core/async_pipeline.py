"""
Core Module: Asynchronous Pipeline & Background Batch Worker
------------------------------------------------------------
Provides non-blocking async execution queues, concurrent retrieval workers,
and thread-pool task dispatchers for RAG inference, verification, and evaluation.
"""

import asyncio
import concurrent.futures
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

# Shared thread pool executor for CPU/IO heavy tasks
_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="compliance_async_worker")

class AsyncPipelineManager:
    """Manages asynchronous query queues, batch jobs, and background workers."""
    
    def __init__(self):
        self._results_cache: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def run_sync_in_thread(self, fn: Callable, *args, **kwargs) -> Any:
        """Executes a synchronous function in the background worker thread pool and waits for result."""
        future = _EXECUTOR.submit(fn, *args, **kwargs)
        return future.result()

    def submit_task(self, task_id: str, fn: Callable, *args, **kwargs) -> concurrent.futures.Future:
        """Submits a background task to the thread pool with tracking."""
        def _wrapper():
            try:
                res = fn(*args, **kwargs)
                with self._lock:
                    self._results_cache[task_id] = {"status": "completed", "result": res, "error": None}
                return res
            except Exception as exc:
                with self._lock:
                    self._results_cache[task_id] = {"status": "failed", "result": None, "error": str(exc)}
                raise exc

        with self._lock:
            self._results_cache[task_id] = {"status": "running", "result": None, "error": None}
            
        return _EXECUTOR.submit(_wrapper)

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Checks the execution status of a submitted background task."""
        with self._lock:
            return self._results_cache.get(task_id)

    async def execute_async_pipeline(
        self,
        retrieval_fn: Callable,
        generation_fn: Callable,
        verifier_fn: Optional[Callable] = None,
        query: str = "",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Executes an end-to-end multi-stage pipeline asynchronously:
          1. Concurrent vector/graph retrieval
          2. Generation (hybrid / LoRA adapter)
          3. Real-time verification / interceptor (optional parallel or chained)
        """
        loop = asyncio.get_event_loop()
        start_t = time.time()
        
        # Stage 1: Async Retrieval
        retrieval_res = await loop.run_in_executor(_EXECUTOR, retrieval_fn, query, kwargs.get("k", 5))
        
        # Stage 2: Generation
        gen_res = await loop.run_in_executor(
            _EXECUTOR,
            generation_fn,
            query,
            retrieval_res,
            kwargs.get("framework")
        )
        
        # Stage 3: Verification (if configured)
        verification_res = None
        if verifier_fn is not None:
            verification_res = await loop.run_in_executor(
                _EXECUTOR,
                verifier_fn,
                query,
                gen_res
            )
            
        elapsed = round(time.time() - start_t, 3)
        return {
            "query": query,
            "retrieval": retrieval_res,
            "generation": gen_res,
            "verification": verification_res,
            "elapsed_seconds": elapsed
        }

# Global Singleton instance
pipeline_manager = AsyncPipelineManager()
