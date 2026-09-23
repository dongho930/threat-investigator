"""조사 대상 URL 정책 (SSRF 방어 1단계: 등록 시점 검사).

DNS 조회 결과와 실제 연결 IP 검사는 조사 Worker에서 요청마다 다시 수행한다(3주차).
여기서는 문자열만으로 판단할 수 있는 위험을 먼저 거른다.
"""

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})
BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa", ".lan", ".intranet")
BLOCKED_HOSTS = frozenset({"localhost", "metadata.google.internal"})

# 브라우저는 "2130706433", "0x7f.1", "0177.0.0.1" 같은 표기도 IP로 해석한다.
# 표준 점 4개 표기가 아닌 숫자형 호스트는 모두 거부한다.
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$", re.IGNORECASE)
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")


class UrlPolicyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class NormalizedUrl:
    original: str
    normalized: str
    host: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.normalized.encode("utf-8")).hexdigest()


def is_ip_allowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """공인(global) 유니캐스트 주소만 허용한다. Worker의 연결 IP 검사에서도 재사용한다."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_ip_allowed(ip.ipv4_mapped)
        if ip.sixtofour is not None or ip.teredo is not None:
            return False
    return ip.is_global and not ip.is_multicast


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def normalize_candidate_url(
    raw: str,
    *,
    max_length: int = 2048,
    allowed_ports: frozenset[int] | set[int] = frozenset({80, 443, 8080, 8443}),
    host_allowlist: frozenset[str] | set[str] = frozenset(),
) -> NormalizedUrl:
    if not isinstance(raw, str):
        raise UrlPolicyError("invalid_type", "URL은 문자열이어야 합니다.")
    candidate = raw.strip()
    if not candidate or len(candidate) > max_length:
        raise UrlPolicyError("invalid_length", "URL 길이가 허용 범위를 벗어났습니다.")
    if _CONTROL_OR_SPACE.search(candidate):
        raise UrlPolicyError("invalid_chars", "URL에 공백이나 제어문자를 넣을 수 없습니다.")

    try:
        parts = urlsplit(candidate)
        port = parts.port
    except ValueError as exc:
        raise UrlPolicyError("invalid_url", "URL 형식이 올바르지 않습니다.") from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlPolicyError("scheme_not_allowed", "http 또는 https URL만 등록할 수 있습니다.")
    if parts.username is not None or parts.password is not None:
        raise UrlPolicyError("userinfo_not_allowed", "사용자 정보가 포함된 URL은 등록할 수 없습니다.")

    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise UrlPolicyError("missing_host", "호스트가 없는 URL입니다.")

    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise UrlPolicyError("invalid_host", "호스트 이름을 해석할 수 없습니다.") from exc

    if port is not None and port not in allowed_ports:
        raise UrlPolicyError("port_not_allowed", "허용되지 않은 포트입니다.")

    if host not in host_allowlist:
        ip = _parse_ip(host)
        if ip is not None:
            if not is_ip_allowed(ip):
                raise UrlPolicyError("ip_not_allowed", "내부·예약 IP 주소는 조사할 수 없습니다.")
        else:
            if all(_NUMERIC_LABEL.match(label) for label in host.split(".")):
                raise UrlPolicyError("ambiguous_numeric_host", "숫자형 호스트 표기는 허용하지 않습니다.")
            if host in BLOCKED_HOSTS or host.endswith(BLOCKED_HOST_SUFFIXES):
                raise UrlPolicyError("host_not_allowed", "내부용 호스트 이름은 조사할 수 없습니다.")
            if "." not in host:
                raise UrlPolicyError("single_label_host", "도메인 형식이 아닌 호스트입니다.")

    netloc = f"[{host}]" if ":" in host else host
    if port is not None and not (scheme == "http" and port == 80) and not (scheme == "https" and port == 443):
        netloc = f"{netloc}:{port}"
    normalized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return NormalizedUrl(original=candidate, normalized=normalized, host=host)
