"""실제 Chromium으로 수집기를 시험한다. 로컬 HTTP 서버에 가상 페이지를 띄운다.

브라우저가 설치되지 않은 환경에서는 건너뛴다(`python -m playwright install chromium`).
"""

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from worker.collector import Artifacts, Collector
from worker.config import WorkerSettings
from worker.url_guard import UrlGuard

PAGES: dict[str, tuple[int, dict[str, str], str]] = {
    "/phish": (
        200,
        {},
        "<title>가상은행 &lt;b&gt;로그인</title><form action='https://collect.example.net/p' method='post'>"
        "<input name='userid'><input type='password' name='pw' value='should-not-be-read'></form>본인 인증",
    ),
    "/r1": (302, {"Location": "/r2"}, ""),
    "/r2": (301, {"Location": "/phish"}, ""),
    "/loop": (302, {"Location": "/loop"}, ""),
    "/ssrf": (302, {"Location": "http://169.254.169.254/latest/meta-data/"}, ""),
    "/popup": (200, {}, "<title>popup</title><script>window.open('/phish')</script>"),
    "/external": (200, {}, "<title>ext</title><script src='http://169.254.169.254/x.js'></script>"),
    "/img-redirect": (302, {"Location": "http://127.0.0.2:8080/x.png"}, ""),
    "/sub-redirect": (200, {}, "<title>sub</title><img src='/img-redirect'>"),
    "/download": (200, {"Content-Disposition": "attachment; filename=a.exe"}, "MZ"),
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        status, headers, body = PAGES.get(self.path, (404, {}, "not found"))
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def site() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture(scope="module")
def collect(site: str) -> Collector:
    port = int(site.rsplit(":", 1)[1])
    settings = WorkerSettings(
        host_allowlist=frozenset({"127.0.0.1"}),
        allowed_ports=frozenset({80, 443, 8080, port}),
        navigation_timeout_ms=8_000,
        settle_ms=300,
        max_redirects=5,
    )
    collector = Collector(
        settings, UrlGuard(host_allowlist=settings.host_allowlist, allowed_ports=settings.allowed_ports)
    )
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            p.chromium.launch().close()
    except Exception as exc:  # 브라우저 미설치
        pytest.skip(f"chromium not available: {exc}")
    return collector


def _hops(a: Artifacts) -> list[tuple[str, int | None, str | None]]:
    return [(h["url"].rsplit("/", 1)[1], h["status"], h["blocked"]) for h in a.redirect_chain["hops"]]


def test_collects_screenshot_and_form_structure_without_values(site: str, collect: Collector) -> None:
    a = collect(f"{site}/phish")
    assert a.outcome == "collected" and a.reason is None
    assert a.screenshot is not None and a.screenshot.startswith(b"\x89PNG")
    dom = a.dom_summary
    assert dom is not None
    assert dom["title"] == "가상은행 <b>로그인"
    assert dom["password_inputs"] == 1
    assert dom["forms"][0]["action_host"] == "collect.example.net"
    assert {"type": "password", "name": "pw", "placeholder": ""} in dom["forms"][0]["inputs"]
    assert "should-not-be-read" not in str(a.files())


def test_redirect_chain_recorded_per_hop(site: str, collect: Collector) -> None:
    a = collect(f"{site}/r1")
    assert a.outcome == "collected"
    assert _hops(a) == [("r1", 302, None), ("r2", 301, None), ("phish", 200, None)]


def test_redirect_loop_stops(site: str, collect: Collector) -> None:
    a = collect(f"{site}/loop")
    assert (a.outcome, a.reason) == ("failed", "too_many_redirects")
    assert len(a.redirect_chain["hops"]) == 6
    assert a.screenshot is None


def test_redirect_to_metadata_ip_blocked_before_request(site: str, collect: Collector) -> None:
    a = collect(f"{site}/ssrf")
    assert (a.outcome, a.reason) == ("failed", "blocked_by_policy")
    assert a.redirect_chain["hops"][-1]["blocked"] == "ip_not_allowed"
    assert a.redirect_chain["hops"][-1]["status"] is None


def test_subresource_to_internal_ip_blocked(site: str, collect: Collector) -> None:
    a = collect(f"{site}/external")
    assert a.outcome == "collected"
    assert a.network_summary["blocked"] == {"ip_not_allowed": 1}


def test_popup_closed(site: str, collect: Collector) -> None:
    a = collect(f"{site}/popup")
    assert a.network_summary["popups_blocked"] == 1


def test_subresource_redirect_violation_recorded(site: str, collect: Collector) -> None:
    a = collect(f"{site}/sub-redirect")
    violations = [r["violation"] for r in a.network_summary["subresource_redirects"]]
    assert violations == ["ip_not_allowed"]


def test_download_not_saved(site: str, collect: Collector) -> None:
    a = collect(f"{site}/download")
    assert a.outcome == "failed"
    assert a.reason in ("navigation_error", "collector_error")
