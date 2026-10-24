"""ASGI comparison application with isolated stats/events, matching RSGI tests."""
import json
import os

from fakeredis.aioredis import FakeRedis

from p2.core.asgi import application as _application
from p2.core import events, volume_stats
from p2.s3.tests import put_profile

_redis = FakeRedis(decode_responses=True)
volume_stats._get_redis = lambda: _redis
events._get_redis = lambda: _redis
if os.environ.get("P2_TEST_PUT_PROFILE") == "1":
    put_profile.install()


async def application(scope, receive, send):
    if scope.get("path") == "/_/test-put-metrics":
        body = json.dumps(put_profile.snapshot(scope.get("query_string") == b"reset=1")).encode()
        await send({"type": "http.response.start", "status": 200, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
        ]})
        await send({"type": "http.response.body", "body": body})
        return
    await _application(scope, receive, send)
