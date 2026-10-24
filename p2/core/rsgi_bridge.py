"""HTTP-only RSGI 1.6 to ASGI adapter for Django fallback requests."""
import asyncio

from granian.rsgi import ProtocolClosed


def _address(value):
    if not value:
        return None
    host, port = value.rsplit(":", 1)
    return host.strip("[]"), int(port)


def asgi_scope(scope):
    headers = []
    seen = set()
    for name, value in scope.headers.items():
        if name in seen:
            continue
        seen.add(name)
        values = scope.headers.get_all(name) if hasattr(scope.headers, "get_all") else [value]
        headers.extend((name.encode("ascii"), item.encode("latin1")) for item in values)
    if "host" not in seen and scope.authority:
        headers.append((b"host", scope.authority.encode("ascii")))
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.0" if scope.http_version == "1" else scope.http_version,
        "method": scope.method,
        "headers": headers,
        # Granian exposes a decoded path. RSGI has no original raw_path field;
        # inventing one or unquoting again corrupts literal percent escapes.
        "path": scope.path,
        "query_string": scope.query_string.encode("ascii"),
        "root_path": "",
        "scheme": scope.scheme,
        "server": _address(scope.server),
        "client": _address(scope.client),
    }


async def call_asgi(application, scope, protocol):
    """Translate body iteration and responses without buffering whole responses.

    RSGI has no ASGI receive/send shim. Streaming ends when this application
    returns; the RSGI HTTP transport deliberately has no close() method.
    """
    body = protocol.__aiter__()
    body_complete = False
    response_complete = asyncio.Event()
    status = None
    headers = None
    transport = None
    disconnect = None

    async def watch_disconnect():
        # Granian's native awaitable passes asyncio.isfuture(), so ensure_future
        # returns it unchanged. It lacks parts of Future's interface (including
        # cancelled()). Keep it behind a real Task before using wait/gather.
        await protocol.client_disconnect()

    async def receive():
        nonlocal body_complete, disconnect
        if not body_complete:
            try:
                chunk = await anext(body)
            except StopAsyncIteration:
                body_complete = True
                return {"type": "http.request", "body": b"", "more_body": False}
            except ProtocolClosed:
                return {"type": "http.disconnect"}
            return {"type": "http.request", "body": chunk, "more_body": True}

        if disconnect is None:
            disconnect = asyncio.create_task(watch_disconnect(), name="p2-rsgi-disconnect")
        completed = asyncio.create_task(response_complete.wait())
        try:
            await asyncio.wait((disconnect, completed), return_when=asyncio.FIRST_COMPLETED)
        finally:
            completed.cancel()
            await asyncio.gather(completed, return_exceptions=True)
        return {"type": "http.disconnect"}

    async def send(message):
        nonlocal status, headers, transport
        if message["type"] == "http.response.start":
            if status is not None:
                raise RuntimeError("ASGI response already started")
            status = message["status"]
            headers = [
                (name.decode("ascii"), value.decode("latin1"))
                for name, value in message.get("headers", [])
            ]
            if not any(name == "x-p2-datapath" for name, _ in headers):
                headers.append(("x-p2-datapath", "django"))
            return
        if message["type"] != "http.response.body" or status is None:
            raise RuntimeError("Invalid ASGI HTTP response sequence")
        if response_complete.is_set():
            raise RuntimeError("ASGI response already completed")
        data = message.get("body", b"")
        more = message.get("more_body", False)
        try:
            if transport is None and not more:
                protocol.response_bytes(status, headers, data)
            else:
                if transport is None:
                    transport = protocol.response_stream(status, headers)
                if data:
                    await transport.send_bytes(data)
        except ProtocolClosed as exc:
            raise OSError("RSGI client disconnected") from exc
        if not more:
            response_complete.set()

    try:
        await application(asgi_scope(scope), receive, send)
    finally:
        if disconnect is not None:
            disconnect.cancel()
            await asyncio.gather(disconnect, return_exceptions=True)
