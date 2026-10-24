"""Opt-in, isolated warm 4-KiB GET comparison, not a performance assertion.

Run explicitly with pytest -s. Uses ephemeral storage/credentials and real
Granian, with 20 persistent HTTP clients and 256 distinct signed object URLs.
The local Python load generator can itself limit throughput; this is not Warp.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import http.client
import json
import os
import statistics
import threading
import time
from urllib.parse import urlsplit

from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
import pytest

from p2.s3.tests.test_rsgi_runtime import runtime  # noqa: F401


@pytest.mark.parametrize("iteration", range(3))
def test_warm_small_get_benchmark(runtime, iteration):
    client, endpoint = runtime
    size, objects, concurrency = 4096, 256, 20
    requests_per_client = int(os.environ.get("P2_BENCH_REQUESTS_PER_CLIENT", "400"))
    requests = []
    credentials = client._request_signer._credentials
    for index in range(objects):
        key = f"bench-{iteration}-{index}"
        client.put_object(Bucket="rsgi-test", Key=key, Body=b"x" * size)
        path = f"/rsgi-test/{key}"
        signed = AWSRequest(method="GET", url=endpoint + path)
        S3SigV4Auth(credentials, "s3", "us-east-1").add_auth(signed)
        requests.append((path, dict(signed.headers.items())))
    address = urlsplit(endpoint)
    # Warm object data and metadata separately from the measured requests.
    with closing(http.client.HTTPConnection(address.hostname, address.port, timeout=10)) as connection:
        for path, headers in requests:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            assert response.status == 200
            assert len(response.read()) == size

    barrier = threading.Barrier(concurrency + 1)

    def transfer(worker):
        latencies = []
        hits = 0
        with closing(http.client.HTTPConnection(address.hostname, address.port, timeout=10)) as connection:
            barrier.wait(timeout=30)
            for index in range(requests_per_client):
                path, headers = requests[(index + worker * 17) % objects]
                started = time.perf_counter()
                connection.request("GET", path, headers=headers)
                response = connection.getresponse()
                assert response.status == 200
                assert len(response.read()) == size
                latencies.append((time.perf_counter() - started) * 1000)
                hits += response.getheader("x-p2-read-cache") == "hit"
        return latencies, hits

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(transfer, worker) for worker in range(concurrency)]
        started = time.perf_counter()
        barrier.wait(timeout=30)
        results = [future.result() for future in futures]
        latencies = sorted(value for values, _ in results for value in values)
        hits = sum(count for _, count in results)
        elapsed = time.perf_counter() - started
    print(json.dumps({
        "iteration": iteration, "requests": len(latencies), "concurrency": concurrency,
        "objects": objects, "object_bytes": size,
        "read_cache_hits": hits,
        "objects_per_second": round(len(latencies) / elapsed, 1),
        "p50_ms": round(statistics.median(latencies), 3),
        "p99_ms": round(latencies[int(len(latencies) * 0.99)], 3),
    }), flush=True)
