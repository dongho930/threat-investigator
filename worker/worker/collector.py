"""Playwright 격리 브라우저로 페이지를 관찰해 증거를 만든다.

지키는 것:
- 모든 요청을 route로 가로채 UrlGuard 검사(스킴·호스트·포트·DNS 결과 IP)를 통과한 것만 보낸다.
- 리다이렉트 체인은 브라우저에 맡기지 않고 한 단계씩 직접 따라가며 단계마다 검사한다.
  (Playwright route는 리다이렉트의 다음 단계를 가로채지 못한다. 하위 자원의 리다이렉트는 기록만 하고,
  3주차 송신 프록시에서 네트워크 수준으로 막는다.)
- 다운로드·Service Worker·새 창 차단, 시간·요청 수·리다이렉트 횟수·텍스트 길이 제한.
- 쿠키·요청 헤더·폼 입력값은 수집하지 않는다. 폼은 구조(입력 종류·이름)만 기록한다.
- 페이지에서 얻은 값은 모두 신뢰하지 않는 데이터로 보고 타입·길이를 다시 검사한다.
- 브라우저·컨텍스트는 with 블록으로 예외가 나도 반드시 닫는다(SC-CE-02).
"""

import json
import logging
import re
from collections import Counter
from contextlib import closing
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from playwright.sync_api import APIRequestContext, BrowserContext, Page, Route, sync_playwright
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

from worker.config import WorkerSettings
from worker.url_guard import Blocked, UrlGuard

logger = logging.getLogger(__name__)

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_MAX_URL = 2048

# 입력값(value)은 읽지 않는다. 구조만 본다.
FORMS_JS = """
(limit) => Array.from(document.forms).slice(0, limit).map((f) => ({
  action: String(f.getAttribute('action') || ''),
  method: String(f.getAttribute('method') || 'get'),
  inputs: Array.from(f.querySelectorAll('input, select, textarea')).slice(0, 50).map((e) => ({
    type: String(e.getAttribute('type') || (e.tagName === 'INPUT' ? 'text' : e.tagName)).toLowerCase(),
    name: String(e.getAttribute('name') || ''),
    placeholder: String(e.getAttribute('placeholder') || ''),
  })),
}))
"""

PAGE_FACTS_JS = """
() => ({
  password_inputs: document.querySelectorAll('input[type=password]').length,
  iframes: document.querySelectorAll('iframe').length,
  links: document.querySelectorAll('a[href]').length,
  meta_refresh: String((document.querySelector('meta[http-equiv=refresh i]') || {}).content || ''),
})
"""


def clean_text(value: object, limit: int) -> str:
    text = _CONTROL.sub(" ", value if isinstance(value, str) else "")
    return text[:limit]


def _as_int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


@dataclass
class Hop:
    url: str
    status: int | None = None
    blocked: str | None = None


@dataclass
class NetworkState:
    """route 처리기가 채우는 요청 통계. 요청·응답 본문이나 헤더는 담지 않는다."""

    requests: int = 0
    blocked: Counter = field(default_factory=Counter)
    hosts: Counter = field(default_factory=Counter)
    resource_types: Counter = field(default_factory=Counter)
    main_frame: Any = None
    main_document_blocked: str | None = None
    unguarded_redirects: list[dict[str, Any]] = field(default_factory=list)
    popups_blocked: int = 0
    navigations: list[str] = field(default_factory=list)


@dataclass
class Artifacts:
    outcome: str  # "collected" | "failed"
    reason: str | None
    redirect_chain: dict[str, Any]
    network_summary: dict[str, Any]
    dom_summary: dict[str, Any] | None = None
    screenshot: bytes | None = None

    def files(self) -> list[tuple[str, bytes, str]]:
        """(증거 종류, 내용, Content-Type) 목록."""
        out: list[tuple[str, bytes, str]] = []
        if self.screenshot is not None:
            out.append(("screenshot", self.screenshot, "image/png"))
        if self.dom_summary is not None:
            out.append(("dom_summary", _json_bytes(self.dom_summary), "application/json"))
        out.append(("redirect_chain", _json_bytes(self.redirect_chain), "application/json"))
        out.append(("network_summary", _json_bytes(self.network_summary), "application/json"))
        return out


def _json_bytes(data: dict[str, Any]) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")


class CachingGuard:
    """한 조사 안에서 같은 출처(스킴·호스트·포트)의 DNS 검사를 반복하지 않도록 결과를 기억한다."""

    def __init__(self, guard: UrlGuard) -> None:
        self.guard = guard
        self._cache: dict[str, str | None] = {}

    def check(self, url: str) -> None:
        try:
            parts = urlsplit(url)
            key = f"{parts.scheme}://{parts.netloc}"
        except ValueError:
            key = url
        if key not in self._cache:
            try:
                self.guard.check(url)
                self._cache[key] = None
            except Blocked as exc:
                self._cache[key] = exc.reason
        reason = self._cache[key]
        if reason is not None:
            raise Blocked(reason)


def trace_redirects(
    request: APIRequestContext, url: str, guard: CachingGuard, settings: WorkerSettings
) -> tuple[list[Hop], str | None]:
    """리다이렉트를 한 단계씩 따라가며 단계마다 목적지를 검사한다. (단계 목록, 실패 사유)를 돌려준다."""
    hops: list[Hop] = []
    current = url
    for _ in range(settings.max_redirects + 1):
        try:
            guard.check(current)
        except Blocked as exc:
            hops.append(Hop(url=current[:_MAX_URL], blocked=exc.reason))
            return hops, "blocked_by_policy"
        try:
            res = request.get(
                current, max_redirects=0, timeout=settings.navigation_timeout_ms, fail_on_status_code=False
            )
        except PlaywrightTimeoutError:
            hops.append(Hop(url=current[:_MAX_URL], blocked="timeout"))
            return hops, "navigation_timeout"
        except PlaywrightError:
            hops.append(Hop(url=current[:_MAX_URL], blocked="connection_failed"))
            return hops, "navigation_error"
        location = res.headers.get("location")
        status = res.status
        res.dispose()
        hops.append(Hop(url=current[:_MAX_URL], status=status))
        if 300 <= status < 400 and location:
            current = urljoin(current, location)
            continue
        return hops, None
    return hops, "too_many_redirects"


class Collector:
    def __init__(self, settings: WorkerSettings, guard: UrlGuard) -> None:
        self.settings = settings
        self.guard = guard

    def __call__(self, url: str) -> Artifacts:
        with sync_playwright() as p:
            with closing(p.chromium.launch(headless=True, chromium_sandbox=self.settings.chromium_sandbox)) as browser:
                width, height = self.settings.viewport
                context = browser.new_context(
                    accept_downloads=False,
                    service_workers="block",
                    viewport={"width": width, "height": height},
                    locale="ko-KR",
                    java_script_enabled=True,
                )
                with closing(context):
                    return self._investigate(context, url)

    def _investigate(self, context: BrowserContext, url: str) -> Artifacts:
        cfg = self.settings
        guard = CachingGuard(self.guard)
        net = NetworkState()

        hops, reason = trace_redirects(context.request, url, guard, cfg)
        chain = {"schema": "redirect_chain/1", "hops": [h.__dict__ for h in hops], "final_url": hops[-1].url}
        if reason is not None:
            logger.info("redirect trace stopped reason=%s hops=%d", reason, len(hops))
            return Artifacts("failed", reason, chain, self._network_summary(net))

        final_url = hops[-1].url
        context.route("**/*", lambda route: self._on_route(route, guard, net))
        page = context.new_page()
        net.main_frame = page.main_frame
        page.set_default_timeout(cfg.navigation_timeout_ms)
        context.on("page", lambda popup: self._close_popup(popup, page, net))
        page.on("request", lambda req: self._on_request(req, guard, net))
        page.on("framenavigated", lambda frame: self._on_navigated(frame, page, net))

        outcome, reason = "collected", None
        try:
            page.goto(final_url, wait_until="load", timeout=cfg.navigation_timeout_ms)
            page.wait_for_timeout(cfg.settle_ms)
        except PlaywrightTimeoutError:
            outcome, reason = "failed", "navigation_timeout"
        except PlaywrightError:
            outcome = "failed"
            reason = "blocked_by_policy" if net.main_document_blocked else "navigation_error"

        dom, shot = None, None
        if net.main_document_blocked is None:
            dom = self._dom_summary(page)
            shot = self._screenshot(page)
            if outcome == "collected" and (dom is None or shot is None):
                outcome, reason = "failed", "collector_error"
        return Artifacts(outcome, reason, chain, self._network_summary(net), dom, shot)

    def _on_route(self, route: Route, guard: CachingGuard, net: NetworkState) -> None:
        # 처리기에서 예외가 나도 요청을 매달아 두지 않는다. 판단할 수 없으면 차단한다(fail-closed).
        try:
            verdict = self._route_verdict(route.request, guard, net)
        except Exception:
            logger.exception("route handler error")
            verdict = "route_error"
        if verdict is None:
            route.continue_()
        else:
            net.blocked[verdict] += 1
            route.abort("blockedbyclient")

    def _route_verdict(self, req: Any, guard: CachingGuard, net: NetworkState) -> str | None:
        net.requests += 1
        net.resource_types[req.resource_type] += 1
        if net.requests > self.settings.max_requests:
            return "request_limit"
        frame = None
        if req.is_navigation_request():
            try:
                frame = req.frame
            except PlaywrightError:
                # 프레임이 만들어지기 전의 탐색 요청 = 새 창(팝업)을 여는 요청
                return "popup"
        try:
            guard.check(req.url)
        except Blocked as exc:
            if frame is not None and frame == net.main_frame:
                net.main_document_blocked = exc.reason
            return exc.reason
        host = _host(req.url)
        if len(net.hosts) < self.settings.max_hosts or host in net.hosts:
            net.hosts[host] += 1
        return None

    def _on_request(self, req: Any, guard: CachingGuard, net: NetworkState) -> None:
        # route가 가로채지 못하는 하위 자원 리다이렉트를 사후에 검사해 기록한다.
        if req.redirected_from is None or len(net.unguarded_redirects) >= 20:
            return
        try:
            guard.check(req.url)
            verdict = None
        except Blocked as exc:
            verdict = exc.reason
        net.unguarded_redirects.append({"url": req.url[:_MAX_URL], "violation": verdict})

    def _on_navigated(self, frame: Any, page: Page, net: NetworkState) -> None:
        if frame == page.main_frame and len(net.navigations) < 20:
            net.navigations.append(frame.url[:_MAX_URL])

    @staticmethod
    def _close_popup(popup: Page, main: Page, net: NetworkState) -> None:
        if popup != main:
            net.popups_blocked += 1
            popup.close()

    def _dom_summary(self, page: Page) -> dict[str, Any] | None:
        cfg = self.settings
        try:
            title = page.title()
            text = page.locator("body").inner_text(timeout=3_000)
            raw_forms = page.evaluate(FORMS_JS, cfg.max_forms)
            facts = page.evaluate(PAGE_FACTS_JS)
        except PlaywrightError:
            logger.warning("dom summary failed")
            return None
        return {
            "schema": "dom_summary/1",
            "final_url": page.url[:_MAX_URL],
            "title": clean_text(title, 300),
            "text_excerpt": clean_text(text, cfg.max_text_chars),
            "forms": self._clean_forms(raw_forms, page.url),
            "password_inputs": _as_int(facts.get("password_inputs") if isinstance(facts, dict) else 0),
            "iframes": _as_int(facts.get("iframes") if isinstance(facts, dict) else 0),
            "links": _as_int(facts.get("links") if isinstance(facts, dict) else 0),
            "meta_refresh": clean_text(facts.get("meta_refresh") if isinstance(facts, dict) else "", 300),
        }

    def _clean_forms(self, raw: object, base_url: str) -> list[dict[str, Any]]:
        if not isinstance(raw, list):
            return []
        forms = []
        for item in raw[: self.settings.max_forms]:
            if not isinstance(item, dict):
                continue
            action = clean_text(item.get("action"), _MAX_URL)
            try:
                action_url = urljoin(base_url, action)
            except ValueError:
                action_url = ""
            inputs = item.get("inputs") if isinstance(item.get("inputs"), list) else []
            forms.append(
                {
                    "action_host": _host(action_url),
                    "method": clean_text(item.get("method"), 10).lower(),
                    "inputs": [
                        {
                            "type": clean_text(i.get("type"), 20),
                            "name": clean_text(i.get("name"), 64),
                            "placeholder": clean_text(i.get("placeholder"), 64),
                        }
                        for i in inputs[:50]
                        if isinstance(i, dict)
                    ],
                }
            )
        return forms

    @staticmethod
    def _screenshot(page: Page) -> bytes | None:
        try:
            return page.screenshot(type="png", full_page=False, animations="disabled", timeout=10_000)
        except PlaywrightError:
            logger.warning("screenshot failed")
            return None

    @staticmethod
    def _network_summary(net: NetworkState) -> dict[str, Any]:
        return {
            "schema": "network_summary/1",
            "requests": net.requests,
            "blocked": dict(net.blocked),
            "hosts": dict(net.hosts),
            "resource_types": dict(net.resource_types),
            "popups_blocked": net.popups_blocked,
            "navigations": net.navigations,
            "unguarded_redirects": net.unguarded_redirects,
        }
