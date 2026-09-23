"""송신 목적지 정책.

조사 Worker가 밖으로 나가는 모든 연결은 이 정책을 통과해야 한다.
DNS는 연결마다 한 번만 조회하고, 조회된 주소가 모두 공인 주소일 때 그중 하나를 골라 **그 IP로 직접** 연결한다.
검사한 주소와 실제 연결 주소가 같으므로, 조회 뒤 주소를 바꾸는 DNS 리바인딩이 통하지 않는다.
"""

import ipaddress
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], list[str]]

BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa", ".lan", ".intranet")
BLOCKED_HOSTS = frozenset({"localhost", "metadata.google.internal"})
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$", re.IGNORECASE)
_HOST_CHARS = re.compile(r"^[a-z0-9.\-:\[\]_]+$")


def is_ip_allowed(ip: IpAddress) -> bool:
    """공인(global) 유니캐스트 주소만 허용한다 (backend·worker와 같은 규칙)."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_ip_allowed(ip.ipv4_mapped)
        if ip.sixtofour is not None or ip.teredo is not None:
            return False
    return ip.is_global and not ip.is_multicast


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    # IPv4를 먼저 시도한다(컨테이너 네트워크가 IPv6를 지원하지 않는 경우가 많다).
    return sorted({str(info[4][0]) for info in infos}, key=lambda a: (":" in a, a))


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str | None = None
    ip: str | None = None

    @classmethod
    def deny(cls, reason: str) -> "Decision":
        return cls(False, reason)


class EgressPolicy:
    def __init__(
        self,
        *,
        allowed_ports: frozenset[int] = frozenset({80, 443, 8080, 8443}),
        host_allowlist: frozenset[str] = frozenset(),
        resolver: Resolver = system_resolver,
    ) -> None:
        self.allowed_ports = allowed_ports
        self.host_allowlist = frozenset(h.lower() for h in host_allowlist)
        self.resolver = resolver

    def decide(self, host: str, port: int) -> Decision:
        host = host.strip().rstrip(".").lower()
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        if not host or len(host) > 253 or not _HOST_CHARS.match(host):
            return Decision.deny("invalid_host")
        if port not in self.allowed_ports:
            return Decision.deny("port_not_allowed")

        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            if host in self.host_allowlist or is_ip_allowed(literal):
                return Decision(True, ip=str(literal))
            return Decision.deny("ip_not_allowed")

        if host not in self.host_allowlist:
            if all(_NUMERIC_LABEL.match(label) for label in host.split(".")):
                return Decision.deny("ambiguous_numeric_host")
            if host in BLOCKED_HOSTS or host.endswith(BLOCKED_HOST_SUFFIXES) or "." not in host:
                return Decision.deny("host_not_allowed")

        try:
            addresses = self.resolver(host, port)
        except (OSError, UnicodeError):
            return Decision.deny("dns_failed")
        if not addresses:
            return Decision.deny("dns_failed")
        parsed: list[IpAddress] = []
        for addr in addresses:
            try:
                parsed.append(ipaddress.ip_address(addr.split("%", 1)[0]))
            except ValueError:
                return Decision.deny("dns_failed")
        # 허용 목록 호스트(개발용 testsites)는 사설 주소여도 통과시킨다. 그 외에는 주소가 하나라도 내부면 거부한다.
        if host not in self.host_allowlist and not all(is_ip_allowed(ip) for ip in parsed):
            return Decision.deny("resolved_ip_not_allowed")
        return Decision(True, ip=str(parsed[0]))
