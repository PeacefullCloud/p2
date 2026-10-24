"""Real application with only Redis redirected to a test-local fake."""
import json
import os

from fakeredis.aioredis import FakeRedis

from p2.core.rsgi import application  # noqa: F401
from p2.core import events, volume_stats
from p2.s3.tests import put_profile

_redis = FakeRedis(decode_responses=True)
volume_stats._get_redis = lambda: _redis
events._get_redis = lambda: _redis
if os.environ.get("P2_TEST_PUT_PROFILE") == "1":
    put_profile.install()

_handler = application.handler


async def _observe_scope(scope, protocol):
    if scope.path == "/_/test-put-metrics":
        protocol.response_bytes(200, [], json.dumps(
            put_profile.snapshot(scope.query_string == "reset=1"),
        ).encode())
        return
    if scope.path.startswith("/_/test-scope/"):
        protocol.response_bytes(200, [], json.dumps({"path": scope.path}).encode())
        return
    await _handler(scope, protocol)


application.handler = _observe_scope
