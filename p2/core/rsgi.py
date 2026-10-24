"""Experimental RSGI entry point, with an explicit HTTP bridge to Django."""
import asyncio
import os
from concurrent.futures import ThreadPoolExecutor

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "p2.core.settings")

if os.environ.get("OTEL_SDK_DISABLED", "false").lower() != "true":
    from p2.core.telemetry import setup_telemetry
    setup_telemetry()

from django.core.asgi import get_asgi_application
from django.conf import settings

_django_app = get_asgi_application()

from p2.core.rsgi_bridge import call_asgi
from p2.s3.rsgi_handler import S3ProxyRSGIApp
from p2.s3.datapath import monitor_loop_lag
from p2.s3.volume_writer import shutdown_writer

async def _django_fallback(scope, protocol):
    await call_asgi(_django_app, scope, protocol)


class RSGIApplication:
    def __init__(self):
        self.handler = S3ProxyRSGIApp(_django_fallback)
        self.monitor = None

    def __rsgi_init__(self, loop):
        # Configure Granian's actual loop, not an unused loop created at import.
        workers = int(os.environ.get("P2_ASGI_THREADPOOL_MAX_WORKERS", "32"))
        loop.set_default_executor(ThreadPoolExecutor(max_workers=workers))
        if settings.S3_BENCHMARK_TIMINGS:
            self.monitor = loop.create_task(monitor_loop_lag())

    async def __call__(self, scope, protocol):
        if scope.proto != "http":
            protocol.close(1008)
            return
        await self.handler(scope, protocol)

    def __rsgi_del__(self, loop):
        loop.run_until_complete(shutdown_writer())
        if self.monitor is not None:
            self.monitor.cancel()
            loop.run_until_complete(asyncio.gather(self.monitor, return_exceptions=True))


application = RSGIApplication()
