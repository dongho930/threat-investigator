"""Worker 측 URL·목적지 검사.

backend의 app/security/url_policy.py와 같은 규칙을 쓰되, 여기서는 DNS 조회 결과까지 확인한다.
조사 중 브라우저가 요청하는 모든 URL(리다이렉트 각 단계, 하위 자원)에 적용한다.

한계: DNS 조회 시점과 실제 연결 시점 사이에 주소가 바뀌는 DNS 리바인딩은 여기서 막지 못한다.
3주차에 송신 프록시가 실제 연결 IP를 다시 검사해 이 틈을 닫는다.
"""

import ipaddress
import re
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})
BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa", ".lan", ".intranet")
BLOCKED_HOSTS = frozenset({"localhost", "metadata.google.internal"})
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$", re.IGNORECASE)

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], list[str]]


class Blocked(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def is_ip_allowed(ip: IpAddress) -> bool:
    """공인(global) 유니캐스트 주소만 허용한다 (backend url_policy.is_ip_allowed와 동일)."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_ip_allowed(ip.ipv4_mapped)
        if ip.sixtofour is not None or ip.teredo is not None:
            return False
    return ip.is_global and not ip.is_multicast


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


class UrlGuard:
    def __init__(
        self,
        *,
        host_allowlist: frozenset[str] = frozenset(),
        allowed_ports: frozenset[int] = frozenset({80, 443, 8080, 8443}),
        resolver: Resolver = system_resolver,
    ) -> None:
        self.host_allowlist = host_allowlist
        self.allowed_ports = allowed_ports
        self.resolver = resolver

    def check(self, url: str) -> None:
        """허용되지 않으면 Blocked(사유 코드)를 던진다."""
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as exc:
            raise Blocked("invalid_url") from exc
        scheme = parts.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            raise Blocked("scheme_not_allowed")
        if parts.username is not None or parts.password is not None:
            raise Blocked("userinfo_not_allowed")
        host = (parts.hostname or "").rstrip(".").lower()
        if not host:
            raise Blocked("missing_host")
        effective_port = port or (443 if scheme == "https" else 80)
        if effective_port not in self.allowed_ports:
            raise Blocked("port_not_allowed")
        if host in self.host_allowlist:
            return

        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            if not is_ip_allowed(literal):
                raise Blocked("ip_not_allowed")
            return
        if all(_NUMERIC_LABEL.match(label) for label in host.split(".")):
            raise Blocked("ambiguous_numeric_host")
        if host in BLOCKED_HOSTS or host.endswith(BLOCKED_HOST_SUFFIXES) or "." not in host:
            raise Blocked("host_not_allowed")

        try:
            addresses = self.resolver(host, effective_port)
        except (OSError, UnicodeError) as exc:
            raise Blocked("dns_failed") from exc
        if not addresses:
            raise Blocked("dns_failed")
        # 조회된 주소 중 하나라도 내부 주소면 거부한다(공인·내부 주소를 섞어 돌려주는 경우 대비).
        for addr in addresses:
            try:
                ip = ipaddress.ip_address(addr.split("%", 1)[0])
            except ValueError as exc:
                raise Blocked("dns_failed") from exc
            if not is_ip_allowed(ip):
                raise Blocked("resolved_ip_not_allowed")
