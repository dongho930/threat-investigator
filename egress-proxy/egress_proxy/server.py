"""조사 Worker 전용 송신 프록시 (HTTP 전달 + CONNECT 터널).

- Worker는 인터넷에 직접 닿지 않는 내부망에 있고, 밖으로 나가는 길은 이 프록시뿐이다.
  그래서 브라우저가 요청 가로채기(route)를 거치지 않고 따라가는 리다이렉트·하위 요청도 여기서 다시 검사된다.
- 연결마다 EgressPolicy로 목적지를 정하고, 검사한 IP로 직접 연결한다(DNS 리바인딩 차단).
- `GET /__check?host=&port=`는 Worker가 증거에 차단 사유를 적기 위해 묻는 조회 전용 경로다. 강제 지점은 실제 연결이다.
- 요청·응답 본문과 헤더는 기록하지 않는다. 로그에는 호스트·포트·판정만 남긴다.
"""

import asyncio
import json
import logging
import re
from urllib.parse import parse_qs, urlsplit

from egress_proxy.policy import Decision, EgressPolicy

logger = logging.getLogger(__name__)

MAX_HEAD_BYTES = 16 * 1024
HEAD_TIMEOUT_S = 10.0
CONNECT_TIMEOUT_S = 10.0
IDLE_TIMEOUT_S = 30.0
MAX_CONNECTION_S = 120.0
UPSTREAM_UNREACHABLE = "upstream_unreachable"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_HOP_BY_HOP = frozenset(
    {"connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate", "te", "upgrade"}
)


def _safe(value: str) -> str:
    return _CONTROL.sub(" ", value)[:200]


def _split_host_port(target: str, default_port: int) -> tuple[str, int]:
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port = target.rpartition(":") if target.count(":") == 1 else (target, "", "")
    if not port:
        return host, default_port
    if not port.isdigit():
        raise ValueError("bad port")
    return host, int(port)


class EgressProxy:
    def __init__(self, policy: EgressPolicy, *, max_connections: int = 200) -> None:
        self.policy = policy
        self._slots = asyncio.Semaphore(max_connections)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._slots.locked():
            await self._reply(writer, 503, "busy")
            return
        async with self._slots:
            try:
                await asyncio.wait_for(self._handle(reader, writer), MAX_CONNECTION_S)
            except (TimeoutError, ConnectionError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                pass
            except Exception:
                logger.exception("proxy error")
            finally:
                writer.close()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT_S)
        if len(head) > MAX_HEAD_BYTES:
            await self._reply(writer, 431, "header_too_large")
            return
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, target, version = lines[0].split(" ")
        except ValueError:
            await self._reply(writer, 400, "bad_request")
            return

        if method == "CONNECT":
            await self._connect(reader, writer, target)
        elif method == "GET" and target.startswith("/__check"):
            await self._check(writer, target)
        elif target.startswith("http://"):
            await self._forward(reader, writer, method, target, version, lines[1:])
        else:
            # https:// 절대 URI, 원점 형식 요청 등은 받지 않는다(HTTPS는 CONNECT로만).
            await self._reply(writer, 400, "unsupported_request")

    async def _check(self, writer: asyncio.StreamWriter, target: str) -> None:
        query = parse_qs(urlsplit(target).query)
        host = (query.get("host") or [""])[0]
        port_raw = (query.get("port") or [""])[0]
        if not port_raw.isdigit():
            decision = Decision.deny("port_not_allowed")
        else:
            decision = await asyncio.to_thread(self.policy.decide, host, int(port_raw))
        body = json.dumps({"allowed": decision.allowed, "reason": decision.reason}).encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        await writer.drain()

    async def _open(self, host: str, port: int) -> tuple[Decision, tuple | None]:
        decision = await asyncio.to_thread(self.policy.decide, host, port)
        logger.info("egress host=%s port=%d allowed=%s reason=%s", _safe(host), port, decision.allowed, decision.reason)
        if not decision.allowed:
            return decision, None
        # 검사한 IP로 직접 연결한다. 호스트 이름을 다시 넘기지 않는다.
        try:
            streams = await asyncio.wait_for(asyncio.open_connection(decision.ip, port), CONNECT_TIMEOUT_S)
        except (OSError, TimeoutError):
            # 목적지 서버가 연결을 받지 않음(이미 내려간 사이트 등). 정책 차단과 구분해 502로 알린다.
            logger.info("egress host=%s port=%d upstream_unreachable", _safe(host), port)
            return Decision(False, UPSTREAM_UNREACHABLE, decision.ip), None
        return decision, streams

    async def _connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target: str) -> None:
        try:
            host, port = _split_host_port(target, 443)
        except ValueError:
            await self._reply(writer, 400, "bad_target")
            return
        decision, streams = await self._open(host, port)
        if streams is None:
            await self._reply(writer, self._status_for(decision), decision.reason or "blocked")
            return
        up_reader, up_writer = streams
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await self._relay(reader, writer, up_reader, up_writer)

    async def _forward(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        method: str,
        target: str,
        version: str,
        header_lines: list[str],
    ) -> None:
        try:
            parts = urlsplit(target)
            host, port = parts.hostname or "", parts.port or 80
        except ValueError:
            await self._reply(writer, 400, "bad_target")
            return
        if parts.username or parts.password:
            await self._reply(writer, 400, "userinfo_not_allowed")
            return
        decision, streams = await self._open(host, port)
        if streams is None:
            await self._reply(writer, self._status_for(decision), decision.reason or "blocked")
            return
        up_reader, up_writer = streams
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        kept = [h for h in header_lines if h and h.split(":", 1)[0].strip().lower() not in _HOP_BY_HOP]
        # 한 연결에 요청 하나만 전달한다. 다음 요청은 브라우저가 새 연결로 보내므로 다시 검사된다.
        head = "\r\n".join([f"{method} {path} {version}", *kept, "Connection: close", "", ""])
        up_writer.write(head.encode("latin-1"))
        await up_writer.drain()
        await self._relay(reader, writer, up_reader, up_writer)

    @staticmethod
    async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while True:
                chunk = await asyncio.wait_for(src.read(65536), IDLE_TIMEOUT_S)
                if not chunk:
                    break
                dst.write(chunk)
                await dst.drain()
        finally:
            if dst.can_write_eof():
                try:
                    dst.write_eof()
                except OSError:
                    pass

    async def _relay(self, c_reader, c_writer, u_reader, u_writer) -> None:
        tasks = [
            asyncio.create_task(self._pipe(c_reader, u_writer)),
            asyncio.create_task(self._pipe(u_reader, c_writer)),
        ]
        try:
            # 서버→클라이언트 방향이 끝나면 연결을 정리한다. 클라이언트가 먼저 보내기를 끝내도 응답은 끝까지 전달한다.
            _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if tasks[1] in pending:
                await asyncio.wait([tasks[1]], timeout=IDLE_TIMEOUT_S)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            u_writer.close()

    @staticmethod
    def _status_for(decision: Decision) -> int:
        return 502 if decision.reason == UPSTREAM_UNREACHABLE else 403

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, status: int, reason: str) -> None:
        texts = {
            400: "Bad Request",
            403: "Forbidden",
            431: "Request Header Fields Too Large",
            502: "Bad Gateway",
            503: "Busy",
        }
        body = json.dumps({"blocked": reason}).encode()
        writer.write(
            f"HTTP/1.1 {status} {texts.get(status, 'Error')}\r\n".encode()
            + f"X-Egress-Blocked: {reason}\r\nContent-Type: application/json\r\nConnection: close\r\n".encode()
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        try:
            await writer.drain()
        except ConnectionError:
            pass


async def serve(proxy: EgressProxy, host: str, port: int) -> asyncio.Server:
    return await asyncio.start_server(proxy.handle, host, port, limit=MAX_HEAD_BYTES * 2)
