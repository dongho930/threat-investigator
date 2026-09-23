"""위협정보 피드 자동 수집기(자동 탐색).

- 공개 피드(기본: Phishing.Database의 신규 피싱 URL 목록)를 주기적으로 받아, 공개된 SHA-256 체크섬과
  맞는지 확인한 뒤 backend 내부 API로 등록한다. 체크섬이 다르면 그 회차는 등록하지 않는다.
- 이 수집기는 목록 파일만 내려받는다. 목록에 있는 URL에는 접속하지 않으며, 조사는 격리 Worker가 한다.
- 인터넷에는 송신 프록시로만 나간다(EGRESS_PROXY_URL 필수). 리다이렉트는 따라가지 않고, 크기를 제한한다.
- 목록의 URL은 공격용 주소이므로 로그에는 건수만 남긴다.

실행: python -m worker.feed
"""

import hashlib
import logging
import os
import re
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from worker.api_client import ApiClient

logger = logging.getLogger(__name__)

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_BAD_CHARS = re.compile(r"[\x00-\x20\x7f]")
MAX_URL_LENGTH = 2048

Fetcher = Callable[[str], bytes]


class FeedError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    return default if raw is None else raw.strip().lower() in ("1", "true", "yes")


@dataclass(frozen=True)
class FeedSettings:
    enabled: bool = field(default_factory=lambda: _env_bool("FEED_ENABLED", False))
    url: str = field(
        default_factory=lambda: os.getenv("FEED_URL", "https://phish.co.za/latest/phishing-links-NEW-today.txt")
    )
    checksum_url: str | None = field(
        default_factory=lambda: (
            os.getenv(
                "FEED_CHECKSUM_URL",
                "https://raw.githubusercontent.com/Phishing-Database/checksums/master/phishing-links-NEW-today.txt.sha256",
            )
            or None
        )
    )
    source: str = field(default_factory=lambda: os.getenv("FEED_SOURCE", "phishing.database"))
    interval_s: int = field(default_factory=lambda: int(os.getenv("FEED_INTERVAL_SECONDS", "3600")))
    retry_s: int = field(default_factory=lambda: int(os.getenv("FEED_RETRY_SECONDS", "60")))
    max_per_run: int = field(default_factory=lambda: int(os.getenv("FEED_MAX_PER_RUN", "20")))
    max_bytes: int = 2 * 1024 * 1024
    timeout_s: float = 30.0
    proxy_url: str | None = field(default_factory=lambda: os.getenv("EGRESS_PROXY_URL") or None)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def make_fetcher(proxy_url: str | None, *, max_bytes: int, timeout_s: float) -> Fetcher:
    """프록시를 거쳐 http(s) 파일을 받는다. 리다이렉트는 따라가지 않고, 크기를 넘으면 실패한다."""
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else {}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies), _NoRedirect)

    def fetch(url: str) -> bytes:
        if urlsplit(url).scheme not in ("http", "https"):
            raise FeedError("bad_feed_url")
        try:
            # 스킴을 위에서 http(s)로 제한했다.
            with opener.open(url, timeout=timeout_s) as res:  # noqa: S310
                data = res.read(max_bytes + 1)
        except OSError as exc:
            raise FeedError("download_failed") from exc
        if len(data) > max_bytes:
            raise FeedError("feed_too_large")
        return data

    return fetch


def parse_checksum(text: bytes) -> str:
    """`sha256sum` 형식(`<hex> *파일명`)이나 hex 한 줄에서 SHA-256 값을 꺼낸다."""
    try:
        first = text.decode("ascii").strip().split()[0]
    except (UnicodeDecodeError, IndexError) as exc:
        raise FeedError("bad_checksum_file") from exc
    if not _HEX64.match(first):
        raise FeedError("bad_checksum_file")
    return first.lower()


def parse_urls(data: bytes, limit: int) -> list[str]:
    """한 줄에 URL 하나. 주석·빈 줄·http(s)가 아닌 줄·너무 긴 줄은 버리고, 순서를 지키며 중복을 없앤다."""
    urls: list[str] = []
    seen: set[str] = set()
    for raw in data.decode("utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or len(line) > MAX_URL_LENGTH or _BAD_CHARS.search(line):
            continue
        if not line.lower().startswith(("http://", "https://")) or line in seen:
            continue
        seen.add(line)
        urls.append(line)
        if len(urls) >= limit:
            break
    return urls


@dataclass
class RunResult:
    status: str
    urls: int = 0
    response: dict | None = None


def run_once(settings: FeedSettings, fetch: Fetcher, api: ApiClient) -> RunResult:
    data = fetch(settings.url)
    if settings.checksum_url:
        expected = parse_checksum(fetch(settings.checksum_url))
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            # 목록과 체크섬이 갱신 시점 차이로 어긋날 수도 있다. 이번 회차는 건너뛰고 다음 주기에 다시 받는다.
            logger.warning("feed checksum mismatch source=%s; skipping this run", settings.source)
            return RunResult("checksum_mismatch")
    urls = parse_urls(data, settings.max_per_run)
    if not urls:
        return RunResult("empty")
    response = api.import_feed(settings.source, urls)
    logger.info(
        "feed run source=%s sent=%d created=%s duplicate=%s rejected=%s capped=%s",
        settings.source,
        len(urls),
        response.get("created"),
        response.get("duplicate"),
        response.get("rejected"),
        response.get("capped"),
    )
    return RunResult("imported", len(urls), response)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = FeedSettings()
    if not settings.enabled:
        logger.info("feed collector disabled (FEED_ENABLED=false); idling")
        while True:
            time.sleep(3600)
    if not settings.proxy_url:
        raise SystemExit("EGRESS_PROXY_URL is required: the feed collector must reach the internet only via the proxy")
    api = ApiClient(os.getenv("API_BASE_URL", "http://backend:8000"), os.getenv("WORKER_API_TOKEN", ""))
    fetch = make_fetcher(settings.proxy_url, max_bytes=settings.max_bytes, timeout_s=settings.timeout_s)
    logger.info(
        "feed collector started source=%s interval=%ds max_per_run=%d checksum=%s",
        settings.source,
        settings.interval_s,
        settings.max_per_run,
        "on" if settings.checksum_url else "OFF",
    )
    while True:
        # 성공(또는 체크섬 불일치·빈 목록)이면 다음 주기까지 쉬고, 다운로드·내부 API 오류면 짧게 쉬고 다시 시도한다.
        # (배포 직후 backend가 아직 뜨지 않은 경우 등으로 한 주기를 통째로 놓치지 않게)
        wait_s = settings.interval_s
        try:
            result = run_once(settings, fetch, api)
            logger.info("feed run status=%s", result.status)
        except FeedError as exc:
            logger.warning("feed run failed reason=%s", exc.reason)
            wait_s = min(settings.interval_s, settings.retry_s)
        except Exception:
            logger.exception("feed run error")
            wait_s = min(settings.interval_s, settings.retry_s)
        time.sleep(wait_s)


if __name__ == "__main__":
    main()
