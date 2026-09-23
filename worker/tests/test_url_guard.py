import ipaddress
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from worker.url_guard import Blocked, ProxyCheck, UrlGuard, is_ip_allowed


def resolver_for(mapping: dict[str, list[str]]):
    def resolve(host: str, port: int) -> list[str]:
        if host not in mapping:
            raise OSError("NXDOMAIN")
        return mapping[host]

    return resolve


GUARD = UrlGuard(
    host_allowlist=frozenset({"testsites"}),
    resolver=resolver_for(
        {
            "public.example.com": ["93.184.216.34"],
            "rebind.example.com": ["10.0.0.5"],
            "mixed.example.com": ["93.184.216.34", "127.0.0.1"],
            "v6.example.com": ["2606:2800:220:1::1"],
            "mapped.example.com": ["::ffff:169.254.169.254"],
            "empty.example.com": [],
        }
    ),
)


def test_public_host_allowed() -> None:
    GUARD.check("https://public.example.com/login")
    GUARD.check("http://v6.example.com:8080/")


def test_allowlisted_dev_host_skips_dns() -> None:
    GUARD.check("http://testsites:8080/phishing.html")


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("file:///etc/passwd", "scheme_not_allowed"),
        ("javascript:alert(1)", "scheme_not_allowed"),
        ("ftp://public.example.com/", "scheme_not_allowed"),
        ("http://user:pw@public.example.com/", "userinfo_not_allowed"),
        ("http://public.example.com:22/", "port_not_allowed"),
        ("http://169.254.169.254/latest/meta-data/", "ip_not_allowed"),
        ("http://127.0.0.1:8080/api", "ip_not_allowed"),
        ("http://[::1]/", "ip_not_allowed"),
        ("http://2130706433/", "ambiguous_numeric_host"),
        ("http://0x7f.1/", "ambiguous_numeric_host"),
        ("http://localhost/", "host_not_allowed"),
        ("http://db.internal/", "host_not_allowed"),
        ("http://backend:8080/", "host_not_allowed"),
        ("http://rebind.example.com/", "resolved_ip_not_allowed"),
        ("http://mixed.example.com/", "resolved_ip_not_allowed"),
        ("http://mapped.example.com/", "resolved_ip_not_allowed"),
        ("http://nxdomain.example.com/", "dns_failed"),
        ("http://empty.example.com/", "dns_failed"),
        ("http://[::1/", "invalid_url"),
        ("http:///nohost", "missing_host"),
    ],
)
def test_blocked(url: str, reason: str) -> None:
    with pytest.raises(Blocked) as exc:
        GUARD.check(url)
    assert exc.value.reason == reason


@pytest.mark.parametrize(
    "ip",
    ["10.1.2.3", "172.16.0.1", "192.168.0.1", "100.64.0.1", "0.0.0.0", "224.0.0.1", "2002:7f00:1::", "fe80::1"],  # noqa: S104
)
def test_internal_ips_not_allowed(ip: str) -> None:
    assert not is_ip_allowed(ipaddress.ip_address(ip))


# ── 송신 프록시 조회(ProxyCheck) ──


def _fake_proxy(responder):
    class H(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            status, body = responder(self.path)
            self.send_response(status)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a: object) -> None:
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_proxy_check_uses_proxy_decision() -> None:
    seen: list[str] = []

    def responder(path: str):
        seen.append(path)
        allowed = "host=public.example.com" in path
        return 200, json.dumps({"allowed": allowed, "reason": None if allowed else "resolved_ip_not_allowed"}).encode()

    srv, url = _fake_proxy(responder)
    guard = UrlGuard(remote_check=ProxyCheck(url), resolver=lambda h, p: pytest.fail("local DNS must not be used"))
    guard.check("https://public.example.com/login")
    with pytest.raises(Blocked) as exc:
        guard.check("http://rebind.example.com/")
    assert exc.value.reason == "resolved_ip_not_allowed"
    assert seen[0].startswith("/__check?host=public.example.com&port=443")
    srv.shutdown()


@pytest.mark.parametrize(
    ("status", "body", "reason"),
    [
        (200, b"not json", "egress_check_failed"),
        (500, b"", "egress_check_failed"),
        (200, json.dumps({"allowed": "yes"}).encode(), "egress_blocked"),
        (200, json.dumps({"allowed": False, "reason": "bad reason\r\ninjected"}).encode(), "egress_blocked"),
        (200, json.dumps([1, 2]).encode(), "egress_blocked"),
    ],
)
def test_proxy_check_fails_closed(status: int, body: bytes, reason: str) -> None:
    srv, url = _fake_proxy(lambda path: (status, body))
    assert ProxyCheck(url)("x.example.com", 80) == reason
    srv.shutdown()


def test_proxy_check_unreachable_is_blocked() -> None:
    assert ProxyCheck("http://127.0.0.1:9", timeout_s=1)("x.example.com", 80) == "egress_check_failed"


@pytest.mark.parametrize("bad", ["https://proxy:3128", "file:///etc", "proxy:3128"])
def test_proxy_check_requires_http_url(bad: str) -> None:
    with pytest.raises(ValueError):
        ProxyCheck(bad)
