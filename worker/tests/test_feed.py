import hashlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from worker.feed import FeedError, FeedSettings, make_fetcher, parse_checksum, parse_urls, run_once

LIST = b"# comment\nhttps://a.example.com/login\n\nhttps://a.example.com/login\nftp://x.example.com/\nhttp://b.example.org/p?q=1\n"
SUM = hashlib.sha256(LIST).hexdigest()


class FakeApi:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str]]] = []

    def import_feed(self, source: str, urls: list[str]) -> dict:
        self.calls.append((source, urls))
        return {"created": len(urls), "duplicate": 0, "rejected": 0, "capped": 0}


def _settings(**kw) -> FeedSettings:
    base = {"enabled": True, "url": "http://feed/list.txt", "checksum_url": "http://feed/list.sha256", "source": "t"}
    base.update(kw)
    return FeedSettings(**base)


def _fetcher(files: dict[str, bytes]):
    return lambda url: files[url]


def test_checksum_verified_list_is_imported() -> None:
    api = FakeApi()
    files = {"http://feed/list.txt": LIST, "http://feed/list.sha256": f"{SUM} *list.txt\n".encode()}
    result = run_once(_settings(), _fetcher(files), api)
    assert result.status == "imported"
    assert api.calls == [("t", ["https://a.example.com/login", "http://b.example.org/p?q=1"])]


def test_checksum_mismatch_imports_nothing() -> None:
    api = FakeApi()
    files = {"http://feed/list.txt": LIST + b"https://injected.example.com/\n", "http://feed/list.sha256": SUM.encode()}
    assert run_once(_settings(), _fetcher(files), api).status == "checksum_mismatch"
    assert api.calls == []


def test_bad_checksum_file_raises() -> None:
    with pytest.raises(FeedError):
        parse_checksum(b"<html>not a checksum</html>")
    with pytest.raises(FeedError):
        parse_checksum(b"")
    assert parse_checksum(f"{SUM.upper()}  list.txt".encode()) == SUM


def test_parse_urls_filters_and_caps() -> None:
    data = b"\n".join(
        [b"https://ok.example.com/1", b"javascript:alert(1)", b"https://bad url.example.com/", b"http://" + b"a" * 3000]
        + [f"https://n{i}.example.com/".encode() for i in range(50)]
    )
    urls = parse_urls(data, limit=5)
    assert urls[0] == "https://ok.example.com/1" and len(urls) == 5
    assert all(u.startswith("https://") for u in urls)


def test_empty_list_does_not_call_api() -> None:
    api = FakeApi()
    assert (
        run_once(_settings(checksum_url=None), _fetcher({"http://feed/list.txt": b"# nothing\n"}), api).status
        == "empty"
    )
    assert api.calls == []


def _serve(routes: dict[str, tuple[int, dict[str, str], bytes]]):
    class H(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            status, headers, body = routes.get(self.path, (404, {}, b""))
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a: object) -> None:
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_fetcher_limits_size_and_refuses_redirects() -> None:
    srv, base = _serve(
        {
            "/ok": (200, {}, b"x" * 10),
            "/big": (200, {}, b"x" * 101),
            "/redirect": (302, {"Location": "http://169.254.169.254/"}, b""),
        }
    )
    fetch = make_fetcher(None, max_bytes=100, timeout_s=5)
    assert fetch(f"{base}/ok") == b"x" * 10
    with pytest.raises(FeedError, match="feed_too_large"):
        fetch(f"{base}/big")
    with pytest.raises(FeedError, match="download_failed"):
        fetch(f"{base}/redirect")
    with pytest.raises(FeedError, match="bad_feed_url"):
        fetch("file:///etc/passwd")
    srv.shutdown()
