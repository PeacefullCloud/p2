"""Opt-in ASGI/RSGI 4-KiB PUT comparison with native commit stage measurements.

Use TMPDIR=/var/tmp to test real disk rather than this host's /tmp tmpfs.
All credentials, databases, and volumes are generated and isolated.
"""
import base64
import binascii
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import http.client
import json
import os
import statistics
import threading
import time
from urllib.parse import urlsplit
from urllib.request import urlopen

from botocore.auth import S3SigV4Auth, SigV4Auth
from botocore.awsrequest import AWSRequest
import pytest

from p2.s3.tests.test_rsgi_runtime import start_runtime
from p2.s3.tests.streaming_signer import signed_put


@pytest.fixture(scope="module", params=["rsgi", "asginl"])
def put_runtime(tmp_path_factory, request):
    sync = os.environ.get("P2_BENCH_METADATA_SYNC", "true")
    if sync not in ("true", "false"):
        raise ValueError("P2_BENCH_METADATA_SYNC must be true or false")
    yield from start_runtime(tmp_path_factory, request.param, 1, profile=True, metadata_sync=sync == "true")


@pytest.mark.parametrize("mode", ["plain", "metadata", "aws-chunked", "signed-chunked", "signed-trailer"])
def test_put_comparison(put_runtime, mode):
    client, endpoint = put_runtime
    payload = b"x" * 4096
    concurrency = 20
    count = int(os.environ.get("P2_BENCH_REQUESTS_PER_CLIENT", "50"))
    address = urlsplit(endpoint)
    credentials = client._request_signer._credentials
    body, extra = payload, {}
    if mode == "metadata":
        extra["x-amz-meta-warp-tag"] = "isolated-benchmark"
    elif mode == "aws-chunked":
        checksum = base64.b64encode((binascii.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "big"))
        body = b"1000\r\n" + payload + b"\r\n0\r\nx-amz-checksum-crc32:" + checksum + b"\r\n\r\n"
        extra = {
            "content-encoding": "aws-chunked", "x-amz-decoded-content-length": "4096",
            "x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
            "x-amz-trailer": "x-amz-checksum-crc32",
        }

    def request_data(path):
        if mode.startswith("signed-"):
            return signed_put(
                endpoint, path, credentials, payload, trailer=mode == "signed-trailer",
                extra={"x-amz-meta-warp-tag": "isolated-benchmark"},
            )
        signed = AWSRequest(method="PUT", url=endpoint + path, data=body, headers=extra)
        signer = SigV4Auth if mode == "aws-chunked" else S3SigV4Auth
        signer(credentials, "s3", "us-east-1").add_auth(signed)
        return body, dict(signed.headers.items())

    # Initialize allocation/auth independently of the measured request set.
    path = f"/rsgi-test/put-warm-{mode}"
    with closing(http.client.HTTPConnection(address.hostname, address.port, timeout=60)) as connection:
        wire, signed_headers = request_data(path)
        connection.request("PUT", path, body=wire, headers=signed_headers)
        response = connection.getresponse()
        response.read()
        assert response.status == 200
    assert client.get_object(Bucket="rsgi-test", Key=f"put-warm-{mode}")["Body"].read() == payload
    with urlopen(endpoint + "/_/test-put-metrics?reset=1", timeout=10) as response:
        json.load(response)
    barrier = threading.Barrier(concurrency + 1)

    def transfer(worker):
        latencies, routes = [], Counter()
        with closing(http.client.HTTPConnection(address.hostname, address.port, timeout=60)) as connection:
            barrier.wait(timeout=30)
            for index in range(count):
                path = f"/rsgi-test/put-{mode}-{worker}-{index}"
                wire, signed_headers = request_data(path)
                started = time.perf_counter()
                connection.request("PUT", path, body=wire, headers=signed_headers)
                response = connection.getresponse()
                response.read()
                assert response.status == 200
                latencies.append((time.perf_counter() - started) * 1000)
                route = response.getheader("x-p2-datapath") or (
                    "asgi" if response.getheader("x-p2-put-fastpath") == "1" else "django"
                )
                routes[route] += 1
        return latencies, routes

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(transfer, worker) for worker in range(concurrency)]
        started = time.perf_counter()
        barrier.wait(timeout=30)
        results = [future.result() for future in futures]
        elapsed = time.perf_counter() - started
    latencies = sorted(value for values, _ in results for value in values)
    routes = sum((route for _, route in results), Counter())
    with urlopen(endpoint + "/_/test-put-metrics", timeout=10) as response:
        stages = json.load(response)
    objects = stages.get("objects", 0)
    print(json.dumps({
        "metadata_sync_and_metasync": os.environ.get("P2_BENCH_METADATA_SYNC", "true") == "true",
        "volume_fdatasync": True,
        "mode": mode, "requests": len(latencies), "routes": routes,
        "objects_per_second": round(len(latencies) / elapsed, 1),
        "p50_ms": round(statistics.median(latencies), 3),
        "p99_ms": round(latencies[int(len(latencies) * .99)], 3),
        "objects_per_batch": round(objects / max(1, stages.get("batches", 0)), 2),
        "mean_native_stages_ms": {
            key: round(value / max(1, objects), 3)
            for key, value in stages.items() if key not in ("objects", "batches")
        },
    }), flush=True)
