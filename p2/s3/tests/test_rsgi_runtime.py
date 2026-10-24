"""End-to-end tests against real Granian, Rust I/O, LMDB, Django, and SigV4."""
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
from urllib.request import urlopen

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet
import pytest

ROOT = Path(__file__).resolve().parents[3]

_BOOTSTRAP = """
import os
import django
django.setup()
from django.core.management import call_command
call_command("migrate", interactive=False, verbosity=0)
from django.contrib.auth.models import User
from p2.api.models import APIKey
from p2.core.models import Storage, Volume
from p2.core.acl import VolumeACL
from p2.s3.constants import TAG_S3_DEFAULT_STORAGE
from p2.storage.local.constants import TAG_ROOT_PATH
user = User.objects.create_user(username="rsgi-test-user")
key = APIKey(user=user, name="integration", access_key=os.environ["P2_TEST_ACCESS_KEY"])
key.set_secret_key(os.environ["P2_TEST_SECRET_KEY"])
key.save()
storage = Storage.objects.create(
    name="test", controller_path="p2.storage.local.controller.LocalStorageController",
    tags={TAG_S3_DEFAULT_STORAGE: True, TAG_ROOT_PATH: os.environ["P2_STORAGE__ROOT"]},
)
volume = Volume.objects.create(name="rsgi-test", storage=storage)
VolumeACL.objects.create(volume=volume, user=user, permissions=["read", "write", "delete", "list", "admin"])
"""


@pytest.fixture(scope="module", params=[1, 2], ids=["one-worker", "two-workers"])
def runtime(tmp_path_factory, request):
    yield from start_runtime(tmp_path_factory, "rsgi", request.param)


def start_runtime(tmp_path_factory, interface, workers, profile=False, metadata_sync=True):
    """Shared isolated launcher for correctness tests and opt-in comparisons."""
    work = tmp_path_factory.mktemp("rsgi-runtime")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = {key: value for key, value in os.environ.items() if not key.startswith("P2_")}
    env.update(
        DJANGO_SETTINGS_MODULE=f"p2.s3.tests.{'put_bench_settings' if profile else 'rsgi_settings'}",
        P2_SECRET_KEY=secrets.token_urlsafe(32),
        P2_FERNET_KEY=Fernet.generate_key().decode(),
        P2_ADMIN_PASSWORD=secrets.token_urlsafe(24),
        P2_STORAGE__ROOT=str(work / "storage"),
        P2_LIBSQL__FILE=str(work / "control.sqlite3"),
        P2_TEST_ACCESS_KEY=secrets.token_hex(10).upper(),
        P2_TEST_SECRET_KEY=secrets.token_urlsafe(30),
        P2_SECURITY__SSL_REDIRECT="false",
        OTEL_SDK_DISABLED="true",
        P2_REQUIRE_NATIVE="1",
        P2_TEST_PUT_PROFILE="1" if profile else "0",
        P2_TEST_METADATA_SYNC="1" if metadata_sync else "0",
    )
    bootstrap = subprocess.run(
        [sys.executable, "-c", _BOOTSTRAP], cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
    )
    if bootstrap.returncode:
        # Do not echo captured migration output, which can contain credentials.
        raise RuntimeError("Isolated RSGI test database bootstrap failed")
    log_path = work / "server.log"
    log = log_path.open("wb")
    process = subprocess.Popen([
        sys.executable, "-m", "granian", "--interface", interface,
        "--host", "127.0.0.1", "--port", str(port), "--workers", str(workers),
        "--loop", "uvloop", "--no-ws", "--log-level", "error",
        f"p2.s3.tests.{'rsgi' if interface == 'rsgi' else 'asgi'}_runtime:application",
    ], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    endpoint = f"http://127.0.0.1:{port}"
    client = boto3.client(
        "s3", endpoint_url=endpoint, region_name="us-east-1",
        aws_access_key_id=env["P2_TEST_ACCESS_KEY"], aws_secret_access_key=env["P2_TEST_SECRET_KEY"],
        config=Config(
            s3={"addressing_style": "path"}, signature_version="s3v4",
            request_checksum_calculation="when_required", response_checksum_validation="when_required",
            retries={"max_attempts": 0}, connect_timeout=2, read_timeout=10, max_pool_connections=16,
        ),
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Granian RSGI worker exited before becoming ready")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("Granian RSGI worker did not become ready")
        yield client, endpoint
    finally:
        client.close()
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()
        # Responses can finish successfully before bridge cleanup fails. Check
        # the server log too, without echoing potentially sensitive log content.
        with log_path.open("rb") as server_log:
            failures = sum(
                b"Application callable raised an exception" in line
                or b"Traceback (most recent call last)" in line
                or b"Failed to publish blob event" in line
                or b"event publish failed" in line
                for line in server_log
            )
        assert failures == 0, f"Granian logged {failures} unhandled application error markers"


@pytest.mark.parametrize("size", [0, 17, 64 * 1024, 5 * 1024 * 1024])
def test_real_put_get_head_and_exact_ranges(runtime, size):
    client, _ = runtime
    data = bytes([(size // 17) % 251]) * size
    key = f"size-{size}.txt"
    written = client.put_object(Bucket="rsgi-test", Key=key, Body=data, ContentType="text/plain")
    assert written["ETag"] == f'"{hashlib.md5(data).hexdigest()}"'
    timings = written["ResponseMetadata"]["HTTPHeaders"]["server-timing"]
    assert "hash_integrity;dur=" in timings
    if size:
        assert "metadata_lock;dur=" in timings
        assert "metadata_commit;dur=" in timings
    read = client.get_object(Bucket="rsgi-test", Key=key)
    assert read["ResponseMetadata"]["HTTPHeaders"]["x-p2-datapath"] == "rsgi"
    assert read["ContentLength"] == size
    assert read["Body"].read() == data
    head = client.head_object(Bucket="rsgi-test", Key=key)
    assert head["ContentLength"] == size
    assert head["ContentType"] == "text/plain; charset=utf-8"
    if size >= 17:
        ranged = client.get_object(Bucket="rsgi-test", Key=key, Range="bytes=2-8")
        assert ranged["ResponseMetadata"]["HTTPStatusCode"] == 206
        assert ranged["Body"].read() == data[2:9]


def test_real_django_fallback_bucket_listing_and_missing_route(runtime):
    client, endpoint = runtime
    assert any(item["Name"] == "rsgi-test" for item in client.list_buckets()["Buckets"])
    # Non-S3 HTTP traffic must also traverse the bridge, not a nonexistent proto.send.
    from urllib.error import HTTPError
    with pytest.raises(HTTPError) as error:
        urlopen(endpoint + "/api/not-a-real-route", timeout=5)
    assert error.value.code == 404


def test_real_fallback_put_publishes_structured_block_event(runtime):
    client, _ = runtime
    payload = b"fallback-event-payload"
    written = client.put_object(
        Bucket="rsgi-test", Key="fallback-event", Body=payload,
        StorageClass="STANDARD",
    )
    assert written["ResponseMetadata"]["HTTPHeaders"]["x-p2-datapath"] == "django"
    assert client.get_object(Bucket="rsgi-test", Key="fallback-event")["Body"].read() == payload
    # Fixture teardown checks publication warnings, not just the successful PUT.


def test_real_metadata_put_stays_native_and_survives_fallback_reads_and_copy(runtime):
    client, _ = runtime
    key, data = "sdk-metadata", b"metadata-payload"
    result = client.put_object(Bucket="rsgi-test", Key=key, Body=data, Metadata={"warp-tag": "test", "color": "blue"})
    assert result["ResponseMetadata"]["HTTPHeaders"]["x-p2-datapath"] == "rsgi"
    for operation in (client.get_object, client.head_object):
        result = operation(Bucket="rsgi-test", Key=key)
        assert result["Metadata"] == {"warp-tag": "test", "color": "blue"}
        if "Body" in result:
            assert result["Body"].read() == data
    ranged = client.get_object(Bucket="rsgi-test", Key=key, Range="bytes=1-3")
    assert ranged["Metadata"] == {"warp-tag": "test", "color": "blue"}
    assert ranged["Body"].read() == data[1:4]
    for directive, metadata in (("COPY", {"warp-tag": "test", "color": "blue"}), ("REPLACE", {"new": "value"})):
        client.copy_object(
            Bucket="rsgi-test", Key="metadata-copy-" + directive,
            CopySource={"Bucket": "rsgi-test", "Key": key},
            MetadataDirective=directive, Metadata={"new": "value"} if directive == "REPLACE" else {},
        )
        assert client.head_object(Bucket="rsgi-test", Key="metadata-copy-" + directive)["Metadata"] == metadata
    with pytest.raises(ClientError) as error:
        client.copy_object(
            Bucket="rsgi-test", Key="metadata-too-big",
            CopySource={"Bucket": "rsgi-test", "Key": key},
            MetadataDirective="REPLACE", Metadata={"too-big": "x" * 2048},
        )
    assert error.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
    client.put_object(Bucket="rsgi-test", Key=key, Body=b"without metadata")
    assert client.head_object(Bucket="rsgi-test", Key=key)["Metadata"] == {}


@pytest.mark.parametrize("algorithm", ["crc32", "crc32c", "sha1", "sha256"])
def test_real_unsigned_trailer_put_stays_native_and_rejects_corruption(runtime, algorithm):
    from urllib.parse import urlsplit
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from p2.s3.tests.test_put_body import framed_put
    client, endpoint = runtime
    raw, headers = framed_put(algorithm=algorithm)
    headers["x-amz-meta-warp-tag"] = "checksum-trailer"
    address = urlsplit(endpoint)
    connection = http.client.HTTPConnection(address.hostname, address.port, timeout=10)
    try:
        for corrupted, forged in ((False, False), (True, False), (False, True)):
            key = f"trailer-{algorithm}-{corrupted}-{forged}"
            path = "/rsgi-test/" + key
            body = raw.replace(b"cdef", b"xxxx") if corrupted else raw
            signed = AWSRequest(method="PUT", url=endpoint + path, data=body, headers=headers)
            SigV4Auth(client._request_signer._credentials, "s3", "us-east-1").add_auth(signed)
            signed_headers = dict(signed.headers.items())
            if forged:
                value = signed_headers["Authorization"]
                signed_headers["Authorization"] = value[:-1] + ("0" if value[-1] != "0" else "1")
            connection.request("PUT", path, body=body, headers=signed_headers)
            response = connection.getresponse()
            response.read()
            if corrupted or forged:
                assert response.status == (403 if forged else 400)
                with pytest.raises(ClientError):
                    client.head_object(Bucket="rsgi-test", Key=key)
            else:
                assert response.status == 200
                assert response.getheader("x-p2-datapath") == "rsgi"
                stored = client.get_object(Bucket="rsgi-test", Key=key)
                assert stored["Body"].read() == b"abcdef"
                assert stored["Metadata"] == {"warp-tag": "checksum-trailer"}
    finally:
        connection.close()


def test_real_crc32c_header_put_stays_native(runtime):
    from p2.s3._native import checksum
    client, _ = runtime
    payload = b"crc32c-header"
    result = client.put_object(
        Bucket="rsgi-test", Key="crc32c-header", Body=payload,
        ChecksumCRC32C=checksum.compute_crc32c(payload),
        Metadata={"warp-tag": "crc32c-header"},
    )
    assert result["ResponseMetadata"]["HTTPHeaders"]["x-p2-datapath"] == "rsgi"
    assert client.get_object(Bucket="rsgi-test", Key="crc32c-header")["Body"].read() == payload


@pytest.mark.parametrize("trailer", [False, True], ids=["signed", "signed-trailer"])
@pytest.mark.parametrize("size", [0, 6, 128 * 1024])
def test_real_signed_streaming_put_stays_native(runtime, trailer, size):
    from urllib.parse import urlsplit
    from p2.s3.tests.streaming_signer import signed_put
    client, endpoint = runtime
    key = f"signed-{trailer}-{size}"
    payload = (b"abcdef" * (size // 6 + 1))[:size]
    body, headers = signed_put(
        endpoint, "/rsgi-test/" + key, client._request_signer._credentials, payload, trailer=trailer,
        chunks=[payload[:2], payload[2:]],
        extra={"x-amz-meta-warp-tag": "verified"},
    )
    address = urlsplit(endpoint)
    connection = http.client.HTTPConnection(address.hostname, address.port, timeout=10)
    try:
        connection.request("PUT", "/rsgi-test/" + key, body=body, headers=headers)
        response = connection.getresponse()
        response.read()
        assert response.status == 200
        assert response.getheader("x-p2-datapath") == "rsgi"
        assert "body_decode;dur=" in response.getheader("server-timing")
    finally:
        connection.close()
    result = client.get_object(Bucket="rsgi-test", Key=key)
    assert result["Body"].read() == payload
    assert result["Metadata"] == {"warp-tag": "verified"}
    assert result["ETag"] == f'"{hashlib.md5(payload).hexdigest()}"'


@pytest.mark.parametrize("trailer", [False, True], ids=["signed", "signed-trailer"])
@pytest.mark.parametrize("mutation", ["payload", "chunk", "terminal", "truncated", "seed", "length", "checksum"])
def test_real_signed_streaming_rejection_leaves_existing_object_unchanged(runtime, trailer, mutation):
    from urllib.parse import urlsplit
    from p2.s3.tests.streaming_signer import signed_put
    client, endpoint = runtime
    key = f"signed-rejected-{trailer}-{mutation}"
    client.put_object(Bucket="rsgi-test", Key=key, Body=b"original")
    extra = {"x-amz-decoded-content-length": "7"} if mutation == "length" else {}
    if mutation == "checksum":
        # A correctly signed stream still must satisfy its integrity headers.
        extra["x-amz-checksum-sha256"] = "AAAA"
    body, headers = signed_put(
        endpoint, "/rsgi-test/" + key, client._request_signer._credentials, b"abcdef", trailer=trailer,
        chunks=[b"ab", b"cdef"], extra=extra,
    )
    if mutation == "payload":
        body = body.replace(b"cdef", b"xxxx")
    elif mutation in ("chunk", "terminal"):
        offset = body.index(b";chunk-signature=") if mutation == "chunk" else body.index(b"0;chunk-signature=") + 1
        offset += len(b";chunk-signature=")
        body = body[:offset] + (b"0" if body[offset:offset + 1] != b"0" else b"1") + body[offset + 1:]
    elif mutation == "seed":
        value = headers["Authorization"]
        headers["Authorization"] = value[:-1] + ("0" if value[-1] != "0" else "1")
    elif mutation == "truncated":
        body = body[:-1]
        # Content-Length is signed. Keep its value unchanged while presenting
        # truncated AWS framing to avoid a network read timeout.
        body += b"!"
    address = urlsplit(endpoint)
    connection = http.client.HTTPConnection(address.hostname, address.port, timeout=10)
    try:
        connection.request("PUT", "/rsgi-test/" + key, body=body, headers=headers)
        response = connection.getresponse()
        error = response.read()
        assert response.status in (400, 403)
        assert b"InternalError" not in error
    finally:
        connection.close()
    assert client.get_object(Bucket="rsgi-test", Key=key)["Body"].read() == b"original"


@pytest.fixture(scope="module")
def asgi_runtime(tmp_path_factory):
    yield from start_runtime(tmp_path_factory, "asginl", 1)


def test_real_asgi_comparison_retains_user_metadata(asgi_runtime):
    client, _ = asgi_runtime
    result = client.put_object(Bucket="rsgi-test", Key="asgi-metadata", Body=b"body", Metadata={"warp-tag": "kept"})
    assert result["ResponseMetadata"]["HTTPHeaders"]["x-p2-put-fastpath"] == "1"
    result = client.get_object(Bucket="rsgi-test", Key="asgi-metadata")
    assert result["Body"].read() == b"body"
    assert result["Metadata"] == {"warp-tag": "kept"}
    assert client.head_object(Bucket="rsgi-test", Key="asgi-metadata")["Metadata"] == {"warp-tag": "kept"}

def test_real_cached_reads_refresh_after_overwrite_and_delete_across_workers(runtime):
    client, _ = runtime
    key = "cached-cross-worker"

    def read(_):
        return client.get_object(Bucket="rsgi-test", Key=key)["Body"].read()

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        for body in (b"old-body", b"replacement-body"):
            client.put_object(Bucket="rsgi-test", Key=key, Body=body)
            assert all(value == body for value in executor.map(read, range(64)))
        client.delete_object(Bucket="rsgi-test", Key=key)

        def missing(_):
            with pytest.raises(ClientError) as error:
                read(None)
            assert error.value.response["Error"]["Code"] == "NoSuchKey"

        list(executor.map(missing, range(32)))


def test_real_keepalive_django_fallback_cleanup(runtime):
    _, endpoint = runtime
    from urllib.parse import urlsplit
    address = urlsplit(endpoint)
    connection = http.client.HTTPConnection(address.hostname, address.port, timeout=5)
    try:
        for _ in range(8):
            connection.request("GET", "/api/not-a-real-route")
            response = connection.getresponse()
            response.read()
            assert response.status == 404
    finally:
        connection.close()


def test_real_encoded_keys_presign_overwrite_delete(runtime):
    client, _ = runtime
    key = "folder/a b+percent%2F.txt"
    for body in (b"first", b"replacement"):
        client.put_object(Bucket="rsgi-test", Key=key, Body=body)
        response = client.get_object(Bucket="rsgi-test", Key=key)
        assert response["Body"].read() == body
    url = client.generate_presigned_url("get_object", Params={"Bucket": "rsgi-test", "Key": key})
    with urlopen(url, timeout=5) as response:
        assert response.read() == b"replacement"
    client.delete_object(Bucket="rsgi-test", Key=key)
    with pytest.raises(ClientError) as error:
        client.get_object(Bucket="rsgi-test", Key=key)
    assert error.value.response["Error"]["Code"] == "NoSuchKey"


def test_real_scope_path_decoding(runtime):
    _, endpoint = runtime
    with urlopen(endpoint + "/_/test-scope/a%20b%2Bpercent%252F.txt", timeout=5) as response:
        observed = json.load(response)
    assert observed["path"] == "/_/test-scope/a b+percent%2F.txt"


def test_real_concurrent_puts_survive_volume_rotation(runtime):
    client, _ = runtime

    def transfer(index):
        data = bytes([index]) * (1024 * 1024)
        key = f"concurrent-{index}"
        client.put_object(Bucket="rsgi-test", Key=key, Body=data)
        read = client.get_object(Bucket="rsgi-test", Key=key)
        assert read["Body"].read() == data

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(transfer, range(36)))


def test_real_multipart_fallback_and_multiblock_rsgi_stream(runtime):
    client, _ = runtime
    key = "multipart-stream"
    upload = client.create_multipart_upload(Bucket="rsgi-test", Key=key)
    chunks = [b"a" * (5 * 1024 * 1024), b"last-block"]
    parts = []
    for number, body in enumerate(chunks, 1):
        response = client.upload_part(
            Bucket="rsgi-test", Key=key, UploadId=upload["UploadId"],
            PartNumber=number, Body=body,
        )
        parts.append({"PartNumber": number, "ETag": response["ETag"]})
    client.complete_multipart_upload(
        Bucket="rsgi-test", Key=key, UploadId=upload["UploadId"],
        MultipartUpload={"Parts": parts},
    )
    response = client.get_object(Bucket="rsgi-test", Key=key)
    assert response["ResponseMetadata"]["HTTPHeaders"]["x-p2-datapath"] == "rsgi"
    assert response["Body"].read() == b"".join(chunks)
