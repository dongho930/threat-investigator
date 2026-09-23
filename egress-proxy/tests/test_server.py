"""프록시를 실제로 띄워 HTTP 전달·CONNECT 터널·차단·DNS 리바인딩 대응을 시험한다."""

import asyncio
import json

from egress_proxy.policy import EgressPolicy
from egress_proxy.server import EgressProxy, serve


async def _upstream() -> tuple[asyncio.Server, int, list[bytes]]:
    """요청 머리를 기록하고 고정 응답을 주는 작은 HTTP 서버(127.0.0.1)."""
    seen: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        seen.append(head)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1], seen


async def _start_proxy(policy: EgressPolicy) -> tuple[asyncio.Server, int]:
    server = await serve(EgressProxy(policy), "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _raw(port: int, data: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    await writer.drain()
    out = await asyncio.wait_for(reader.read(), 5)
    writer.close()
    return out


def _policy(up_port: int, **kw) -> EgressPolicy:
    return EgressPolicy(allowed_ports=frozenset({80, 443, up_port}), host_allowlist=frozenset({"127.0.0.1"}), **kw)


def test_http_forward_rewrites_request_and_strips_proxy_headers() -> None:
    async def scenario():
        up, up_port, seen = await _upstream()
        proxy, port = await _start_proxy(_policy(up_port))
        async with up, proxy:
            resp = await _raw(
                port,
                f"GET http://127.0.0.1:{up_port}/p?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n"
                "Proxy-Authorization: Basic secret\r\nProxy-Connection: keep-alive\r\n\r\n".encode(),
            )
        return resp, seen

    resp, seen = asyncio.run(scenario())
    assert resp.endswith(b"hello")
    head = seen[0].decode()
    assert head.startswith("GET /p?q=1 HTTP/1.1\r\n")
    assert "Proxy-Authorization" not in head and "Proxy-Connection" not in head
    assert "Connection: close" in head


def test_connect_tunnel_relays_bytes() -> None:
    async def scenario():
        up, up_port, seen = await _upstream()
        proxy, port = await _start_proxy(_policy(up_port))
        async with up, proxy:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(f"CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            await writer.drain()
            established = await reader.readuntil(b"\r\n\r\n")
            writer.write(b"GET /tunneled HTTP/1.1\r\nHost: x\r\n\r\n")
            await writer.drain()
            body = await asyncio.wait_for(reader.read(), 5)
            writer.close()
        return established, body, seen

    established, body, seen = asyncio.run(scenario())
    assert established.startswith(b"HTTP/1.1 200")
    assert body.endswith(b"hello")
    assert seen[0].startswith(b"GET /tunneled")


def test_blocked_destinations_get_403_with_reason() -> None:
    async def scenario():
        proxy, port = await _start_proxy(EgressPolicy())
        async with proxy:
            meta = await _raw(port, b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: x\r\n\r\n")
            tunnel = await _raw(port, b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: x\r\n\r\n")
            https_abs = await _raw(port, b"GET https://example.com/ HTTP/1.1\r\nHost: x\r\n\r\n")
        return meta, tunnel, https_abs

    meta, tunnel, https_abs = asyncio.run(scenario())
    assert meta.startswith(b"HTTP/1.1 403") and b"X-Egress-Blocked: ip_not_allowed" in meta
    assert tunnel.startswith(b"HTTP/1.1 403") and b"ip_not_allowed" in tunnel
    assert https_abs.startswith(b"HTTP/1.1 400")


def test_check_endpoint_reports_decision() -> None:
    async def scenario():
        proxy, port = await _start_proxy(EgressPolicy())
        async with proxy:
            out = await _raw(port, b"GET /__check?host=169.254.169.254&port=80 HTTP/1.1\r\nHost: x\r\n\r\n")
        return out

    body = asyncio.run(scenario()).split(b"\r\n\r\n", 1)[1]
    assert json.loads(body) == {"allowed": False, "reason": "ip_not_allowed"}


def test_connects_to_checked_ip_and_resolves_once(monkeypatch) -> None:
    """DNS 리바인딩 대응: 두 번째 조회부터 내부 주소를 돌려줘도, 프록시는 한 번 조회해 검사한 IP로만 연결한다."""
    calls: list[str] = []

    def rebinding_resolver(host: str, port: int) -> list[str]:
        calls.append(host)
        return ["93.184.216.34"] if len(calls) == 1 else ["127.0.0.1"]

    connected: list[str] = []

    async def fake_open_connection(host, port, **kw):
        connected.append(host)
        raise ConnectionRefusedError("test")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    async def scenario():
        server = await serve(EgressProxy(EgressPolicy(resolver=rebinding_resolver)), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            # open_connection을 가짜로 바꿨으므로 클라이언트는 저수준 create_connection으로 붙는다.
            loop = asyncio.get_running_loop()
            transport, _ = await asyncio.wait_for(loop.create_connection(asyncio.Protocol, "127.0.0.1", port), 5)
            transport.write(b"CONNECT rebind.example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n")
            await asyncio.sleep(0.3)
            transport.close()

    asyncio.run(scenario())
    assert calls == ["rebind.example.com"]
    assert connected == ["93.184.216.34"]


def test_unreachable_upstream_gets_502_not_silent_close() -> None:
    """정책은 통과했지만 목적지가 연결을 받지 않으면(내려간 사이트) 조용히 끊지 않고 502로 알린다."""

    async def scenario():
        # 127.0.0.1의 닫힌 포트: 허용 목록으로 정책은 통과시키고, 연결은 거부된다.
        policy = EgressPolicy(allowed_ports=frozenset({9}), host_allowlist=frozenset({"127.0.0.1"}))
        proxy, port = await _start_proxy(policy)
        async with proxy:
            tunnel = await _raw(port, b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: x\r\n\r\n")
            plain = await _raw(port, b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: x\r\n\r\n")
        return tunnel, plain

    tunnel, plain = asyncio.run(scenario())
    for resp in (tunnel, plain):
        assert resp.startswith(b"HTTP/1.1 502") and b"X-Egress-Blocked: upstream_unreachable" in resp
