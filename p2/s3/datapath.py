"""Small shared utilities for the experimental data plane."""
import asyncio
from contextlib import asynccontextmanager
from time import perf_counter

LOOP_LAG_MS = 0.0


async def monitor_loop_lag(interval=0.1):
    """Sample scheduling delay only when experimental timings are enabled."""
    global LOOP_LAG_MS
    loop = asyncio.get_running_loop()
    while True:
        expected = loop.time() + interval
        await asyncio.sleep(interval)
        LOOP_LAG_MS = max(0.0, (loop.time() - expected) * 1000)


class ByteBudget:
    """Bound admitted PUT payload bytes, including queued/in-flight writes."""

    def __init__(self, capacity):
        if capacity <= 0:
            raise ValueError("PUT byte budget must be positive")
        self.capacity = capacity
        self.used = 0
        self.condition = asyncio.Condition()

    @asynccontextmanager
    async def reserve(self, size):
        if not 0 <= size <= self.capacity:
            raise ValueError("PUT exceeds byte budget")
        async with self.condition:
            await self.condition.wait_for(lambda: self.used + size <= self.capacity)
            self.used += size
        try:
            yield
        finally:
            async with self.condition:
                self.used -= size
                self.condition.notify_all()


class RequestTimings:
    def __init__(self):
        self.values = {}
        self.started = self.stage_started = perf_counter()

    def mark(self, name):
        now = perf_counter()
        self.values[name] = (now - self.stage_started) * 1000
        self.stage_started = now

    def header(self):
        self.values["loop_lag_sample"] = LOOP_LAG_MS
        self.values["total"] = (perf_counter() - self.started) * 1000
        return "server-timing", ", ".join(
            f"{name};dur={duration:.3f}" for name, duration in self.values.items()
        )


async def await_commit(coroutine):
    """Keep payload admission reserved until a submitted commit really finishes.

    Cancelling the HTTP task cannot cancel already-submitted disk I/O. Wait for
    it before releasing its memory budget, then propagate the cancellation.
    """
    task = asyncio.create_task(coroutine)
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            if not cancelled:
                raise
    if cancelled:
        if not task.cancelled():
            task.exception()
        raise asyncio.CancelledError
    return task.result()
