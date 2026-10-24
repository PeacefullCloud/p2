# RSGI data-plane experiment

Branch: `experiment/rsgi-data-plane`. This is an experiment, not a measured
claim that RSGI is faster for every workload. Use a separate test deployment
and storage root, not production data.

Validated against Granian 2.7.7 and the supplied RSGI 1.6 specification.

## What changed

- Native launcher and Compose select `p2.core.rsgi:application`.
- Ordinary SigV4 GET, HEAD, PUT, and non-versioned DELETE bypass Django.
- Small GET (up to 64 KiB by default) uses a bounded metadata/payload LRU and
  `response_bytes`. A hit checks LMDB's latest committed transaction ID, avoiding
  thread dispatch, JSON parsing, file I/O, and static response-header rebuilding.
  Authorization and request-specific CORS still run on every request.
- Larger single-block GET uses RSGI 1.6 `response_file_range`, with the volume-file
  offset and **exclusive** end. Payload bytes do not pass through Python.
  This does not promise kernel `sendfile` or end-to-end zero-copy.
- Larger multi-block GET uses `response_stream` and its returned transport.
  Read paths do not initialize or preallocate the write pool.
- Django fallback has a real HTTP RSGI-to-ASGI adapter. Duplicate response
  headers, body streaming, IPv6 addresses, disconnects, and HTTP/2 authority
  are handled. Granian's RSGI path is already decoded; it is not unquoted again.
- PUT uses `await protocol()` instead of accumulating and joining Python chunks.
  Ordinary SDK user metadata and CRC32C checksums stay on the native path.
  Bounded `STREAMING-UNSIGNED-PAYLOAD-TRAILER` uploads are decoded strictly,
  checked against declared size and every declared checksum, and then written
  through the same batch committer. Request signatures are still verified.
  Bounded `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` and its `-TRAILER` variant
  also stay native: successful request authentication supplies the derived
  signing context, every chunk signature (including the terminal empty chunk)
  is verified, and signed trailers receive a separate canonical-trailer
  signature check. No object allocation or metadata mutation precedes these
  checks. Unsupported schemes still defer to the existing Django implementation.
  Hashing, integrity checks, metadata reads, and allocation share one off-loop
  preparation call. The existing Rust writer and LMDB batch committer remain.
- Rust's `write_blocks_shared` retains immutable Python buffers until I/O
  completion, avoiding the previous Python-bytes-to-Rust-Vec payload copy.
- Allocations lease an owned descriptor until write/sync completion, so volume
  rotation cannot close an in-flight write's file. Data sync is still coalesced
  once per volume file, not once per descriptor lease.
  Native pool initialization/allocation release the GIL while preallocating or
  waiting for their lock, so offloading them actually lets Python keep running.
- API-key generation checks and RSGI bucket generation checks await the cache
  backend rather than making synchronous Redis calls on the event loop. Checks
  remain throttled to one second per worker/key and concurrent checks coalesce.
  This retains the existing freshness/error policy; it is not immediate revocation.
- RSGI reads current LMDB metadata and cold small-object payloads in one
  off-loop call. Cache entries carry the metadata snapshot's transaction ID.
  Any committed write in that bucket, including another worker's overwrite,
  deletion, or compaction update, invalidates earlier snapshots. This is
  deliberately coarse invalidation, not a TTL; write-heavy traffic may get
  little benefit. The existing ASGI metadata cache is unchanged.
- Structured event fields such as block lists are JSON-encoded before Redis
  Streams publication. Existing scalar fields keep their wire format.

LMDB has **not** been replaced. Its one-writer-per-environment constraint still
exists. Moving its reads off-loop prevents page faults from stopping all
requests on that worker; it does not make the database intrinsically faster.

## Build and launch

The extension API changed. Old committed wheels are not valid for this branch.
From the repository root, with Rust, maturin, and project dependencies installed:

```bash
VIRTUAL_ENV="$PWD/.venv" maturin develop --release \
  --manifest-path p2/s3/rust_ext/Cargo.toml
```

Then run the existing native launcher:

```bash
P2_GRANIAN_INTERFACE=rsgi bash scripts/run_without_docker.sh
```

The script may rebuild/stage wheels if sources or stubs are newer than the
installed extension. Set worker count in `.env` with `P2_GRANIAN_WORKERS`.
The launcher still starts the existing worker/gRPC services and applies
migrations, so use a dedicated test configuration.

For Docker, regenerate wheels **before** building the image:

```bash
FORCE_REBUILD=1 bash scripts/build_rust_ext.sh
docker compose build
```

The image validates the new native symbol and fails early on stale wheels.
Pre-existing Compose `venv` volumes can still contain old packages; validate
the loaded extension inside your test container. Do not delete an existing
deployment's volumes just to run this experiment.

## Compare ASGI and RSGI

Use the same branch, hardware, workers, client concurrency, object sizes,
dataset, TLS configuration, and durability settings. Restart between modes.

```bash
P2_GRANIAN_INTERFACE=asginl bash scripts/run_without_docker.sh
P2_GRANIAN_INTERFACE=rsgi bash scripts/run_without_docker.sh
```

These commands are alternatives, not two simultaneous servers on port 8787.
Both modes include the shared-buffer Rust writer and descriptor-lifetime fix;
the comparison isolates the entry-point/data-path differences, not every
change relative to master. RSGI also changes metadata-cache and I/O scheduling
behavior, so it is **not** a pure protocol-adapter microbenchmark.

Use your existing S3 load generator (for example MinIO Warp), on a separate
client host when measuring saturation. Use a disposable benchmark bucket.
Compare at least:

| Dimension | Suggested values |
| --- | --- |
| Object sizes | 4 KiB, 64 KiB, 1 MiB, 16 MiB |
| Operations | GET, HEAD, PUT, mixed |
| Client concurrency | 1, 8, 32, 128 |
| Server workers | 1, 2, 4, 8 |
| Dataset | Fresh/small, larger than available RAM, aged/overwritten |
| Cache state | Warm; cold on a dedicated test host |

Record operations/s, MiB/s, p50/p95/p99, errors, per-worker CPU/RSS, disk
utilization, and client CPU. Ensure enough independent connections reach all
workers. Do not drop host caches on a shared/production machine.

For restart-sensitive degradation, compare the **same populated dataset**
before and after restart, not a fresh bucket against an aged one.

## Optional timings

Set in `.env`:

```dotenv
P2_S3__BENCHMARK_TIMINGS=true
```

RSGI fast-path responses include `x-p2-datapath: rsgi`; responses through the
Django bridge include `x-p2-datapath: django`. This distinguishes routing from
server interface selection. With timings enabled, GET/HEAD also include
`x-p2-read-cache: hit|miss`, and `Server-Timing` includes:

- `auth`, `volume`, `permission`
- GET/HEAD: `metadata_read` (cache lookup, or thread dispatch, LMDB get, JSON
  decoding, and small-payload read on a miss)
- PUT: `admission`, `body_receive`, `prepare`, `hash_integrity`,
  `write_metadata`
- AWS chunked PUT (including signature verification): `body_decode` inside `prepare`
- Batched non-empty PUT: `write_queue`, `data_write`, `data_sync`,
  `metadata_lock`, `metadata_commit`
- `loop_lag_sample`: most recent per-worker scheduling-delay sample, taken
  every 100 ms. It is not a request duration or a p99 measurement.
- `total`: time until response headers are constructed, **not** client-observed
  latency or completed GET file transfer.

Sub-stages overlap their parent durations; do not add all fields together.
`metadata_commit` includes puts plus transaction commit after lock acquisition.
`write_queue` includes queue wait and thread dispatch. Shared batch durations
are attributed to each participating request, not divided by batch size.
Zero-byte PUT uses a direct off-loop metadata transaction and has no batch
sub-stage fields.

If `metadata_lock` dominates at saturation, investigate batch sizing and
writer coordination, then metadata sharding or a different engine. If
`data_sync` dominates, a database/language switch will not remove that latency.
If Python CPU dominates, move a larger part of request processing into Rust.

## Memory and durability

Defaults, per worker:

```dotenv
P2_S3__RSGI__MAX_BODY_BYTES=67108864
P2_S3__RSGI__INFLIGHT_BYTES=268435456
P2_S3__RSGI__SMALL_READ_BYTES=65536
P2_S3__RSGI__READ_CACHE_BYTES=67108864
P2_S3__RSGI__READ_CACHE_ENTRIES=10000
```

The effective fast-path body limit is also capped by the volume size. The
admission budget is reserved from declared Content-Length **before** body
receipt, and held through commit completion, even after HTTP-task cancellation.
AWS framed PUTs reserve twice their encoded length for the retained
encoded/decoded buffers; requests that cannot fit defer before body consumption.
Eight workers can therefore admit about 2 GiB of PUT payloads at these defaults.
This is a payload-admission bound, not a total-RSS bound: server/socket buffers,
Python objects, GET streams, and Django fallback traffic are outside it.
Tune Granian connection/backpressure limits and workload sizes accordingly.

The read cache holds at most 64 MiB of payloads and 10,000 entries **per worker**.
Metadata/header overhead is outside the payload-byte limit. Eight workers can
therefore retain another 512 MiB of payloads. Set `READ_CACHE_ENTRIES=0` to disable
the cache, or `SMALL_READ_BYTES=0` to retain native file/stream responses for
nonempty GETs. Compare these settings explicitly for large or mixed workloads.
Warm small-object results now include application-level payload caching, not
only kernel page caching.

Do not weaken durability to report a performance win. Keep these settings
identical across runs:

```dotenv
P2_S3__VOLUME__FDATASYNC=true
P2_S3__METADATA__LMDB__SYNC=true
P2_S3__METADATA__LMDB__METASYNC=true
```

Volume data sync alone does **not** guarantee that LMDB object names/metadata
survive a power loss. This experiment does not redesign recovery, directory
fsync, compaction coordination, or provide a new crash-durability guarantee.

## Compatibility boundary

Before consuming a PUT body, the handler defers multipart, unknown/oversized
lengths, unsupported streaming/trailer schemes, copy requests, encryption,
tagging/ACL, unsupported checksums, and other specialized requests to Django.
Unsigned and HMAC-SHA256-signed AWS checksum-trailer streams support CRC32,
CRC32C, SHA1, and SHA256. Signed streams without trailers are also supported;
their final empty chunk must have a valid signature. Signed streams are never
decoded as unsigned. Signatures are checked with constant-time comparisons
before storage changes, and declared checksums are independently validated.
User metadata is stored and returned on
GET/HEAD, including ranged Django reads, with a 2-KiB metadata limit.
Range/conditional requests, non-auth query parameters, legacy objects, and
versioned mutations also use Django. This preserves the existing implementation
of those features; it does not assert that every existing S3 feature is complete.
WebSockets are not bridged; launch with `--no-ws`.

## Tests

Use a test-only secret, not deployment credentials:

```bash
P2_SECRET_KEY=rsgi-tests-only OTEL_SDK_DISABLED=true .venv/bin/python -m pytest -q \
  p2/s3/tests/test_rsgi.py \
  p2/s3/tests/test_read_cache.py \
  p2/s3/tests/test_put_body.py \
  p2/s3/tests/test_rsgi_storage.py \
  p2/s3/tests/test_rsgi_runtime.py \
  p2/core/tests/test_events.py
```

Runtime tests create temporary SQLite/LMDB/volume storage, use a fake Redis
instance, generate ephemeral credentials, and launch real Granian with one and
two workers, bound only to loopback. They exercise native I/O and signed S3 operations,
including exact file offsets, empty objects, encoded/presigned keys, Django
fallback, multipart upload/multi-block streaming, and concurrent volume rotation.
They also check structured event publication, cross-worker cached overwrite/
delete freshness, cache limits, and server logs for bridge/publication failures.
Signed-upload tests use an independent botocore/stdlib client, fixed chain
anchors from AWS's published trailer example, multiple chunks, empty bodies,
forged seeds/chunks/trailers, reordered chunks, bad lengths/checksums, and
truncated framing. Real one/two-worker tests verify that rejected signed uploads
cannot overwrite an existing object.

### Opt-in local GET comparison

```bash
P2_SECRET_KEY=rsgi-benchmark-only OTEL_SDK_DISABLED=true .venv/bin/python -m pytest -q -s \
  p2/s3/tests/bench_rsgi_get.py
```

This uses the isolated runtime fixture, 256 distinct 4-KiB objects, 20 persistent
HTTP connections, and three repetitions each for one and two Granian workers.
Each repetition measures 8,000 signed GETs after warmup. It does not run during
normal test discovery. No deployment data or credentials are used.

The Python client and server share the same host, so client CPU and unrelated
host activity can limit throughput. This is a relative smoke measurement, not
a substitute for Warp on an independent client host. It does not establish a
speedup over master, cold storage, larger-than-RAM datasets, or mixed traffic.

Local observations before and after the small-read fix (medians across three
repetitions, timing headers enabled, data/metadata sync unchanged):

| Workers | Before objects/s | After objects/s | Before p50 / p99 (ms) | After p50 / p99 (ms) |
| --- | ---: | ---: | ---: | ---: |
| 1 | 3,147 | 4,061 | 6.053 / 11.901 | 4.198 / 14.960 |
| 2 | 3,463 | 3,917 | 4.934 / 13.429 | 4.043 / 16.424 |

All 48,000 measured GETs succeeded in each version. Final cache hits were 100%
with one worker and about 96.7% with two: warmup used one connection, leaving
the other worker to populate its cache during the measured phase. Throughput
and median latency improved in this local run, but p99 did not. The previously
reported 7,000+ Warp objects/s has **not** been demonstrated or restored here.
Repeat the original Warp workload before drawing a deployment conclusion.

### Opt-in disk-backed PUT comparison

```bash
TMPDIR=/var/tmp P2_SECRET_KEY=rsgi-benchmark-only OTEL_SDK_DISABLED=true \
  .venv/bin/python -m pytest -q -s p2/s3/tests/bench_s3_put.py
```

The temporary servers use one worker, 20 persistent connections, 4-KiB objects,
fake Redis, and both data and metadata sync enabled. The existing ASGI handler
is the comparison, on this branch with the same native writer. Each mode sends
1,000 PUTs by default; set `P2_BENCH_REQUESTS_PER_CLIENT=200` for 4,000.
Modes cover plain, user metadata, unsigned checksum trailers, signed chunks,
and signed checksum trailers. Signed modes also carry user metadata.
On this host `/tmp` is tmpfs, so use the disk-backed `/var/tmp` when investigating
sync/commit time. These test fixtures never edit `.env` or use deployment storage.

The initial short comparison reproduced the routing problem: RSGI metadata
PUTs entered Django at 255 objects/s, versus 1,297 on ASGI's fast path.
After the fix, all 1,000 metadata PUTs used RSGI directly at 1,147 objects/s;
unsigned trailer PUTs rose from 254 to 923 objects/s. These short samples do
**not** establish sustained throughput.

Longer runs were variable and did not demonstrate restoration to 3,000–4,000
PUTs/s. A 4,000-request RSGI run recorded 1,109 / 383 / 313 objects/s for plain /
metadata / unsigned-trailer PUTs. The corresponding ASGI run recorded
972 / 1,000 / 871. RSGI's slower samples spent about 17–21 ms in metadata
commit and 6–8 ms in data sync per participating request's batch, with negligible
writer-lock wait in this one-worker experiment. All requests succeeded.
Filesystem/host activity and commit batch sizes limit these comparisons.

For an explicit **test-only durability sensitivity control**, set
`P2_BENCH_METADATA_SYNC=false`. This disables both LMDB sync flags only in the
temporary server while retaining data fdatasync, matching the repository's
metadata defaults. It is not a safe durability-equivalent performance win.
In one run metadata commits dropped below 1 ms, but data sync still varied and
throughput did not consistently recover. Deployment flags were left unchanged.

Confirm request routing and the old benchmark's durability settings before
attributing the entire reported slowdown to the server interface. The current
deployment configuration enables both LMDB sync flags; their historical values
for the earlier 3,000–4,000 objects/s result have not been established.
