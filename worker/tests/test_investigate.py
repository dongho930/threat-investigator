import json
import uuid

import pytest

from worker.api_client import ApiClient, Target
from worker.collector import Artifacts, CachingGuard, clean_text
from worker.investigate import Investigator
from worker.messages import JobMessage
from worker.url_guard import Blocked, UrlGuard


class FakeApi:
    def __init__(self, target: Target | None) -> None:
        self.target = target
        self.uploads: list[tuple[str, bytes, str]] = []
        self.completed: list[tuple[str, str | None]] = []
        self.jobs: list[object] = []

    def claim(self, case_id: object, job_id: object) -> Target | None:
        self.jobs.append(job_id)
        return self.target

    def upload_evidence(self, case_id: object, job_id: object, kind: str, data: bytes, content_type: str) -> dict:
        self.jobs.append(job_id)
        self.uploads.append((kind, data, content_type))
        return {}

    def complete(self, case_id: object, job_id: object, outcome: str, reason: str | None = None) -> dict:
        self.jobs.append(job_id)
        self.completed.append((outcome, reason))
        return {}


def _job() -> JobMessage:
    return JobMessage(job_id=uuid.uuid4(), case_id=uuid.uuid4(), stage="investigate", attempt=1)


def _artifacts(**kw: object) -> Artifacts:
    base = {
        "outcome": "collected",
        "reason": None,
        "redirect_chain": {"hops": []},
        "network_summary": {"requests": 1},
        "dom_summary": {"title": "t"},
        "screenshot": b"\x89PNG\r\n\x1a\n",
    }
    base.update(kw)
    return Artifacts(**base)  # type: ignore[arg-type]


def test_uses_url_from_api_not_message() -> None:
    job = _job()
    api = FakeApi(Target(case_id=job.case_id, url="https://from-db.example.com/"))
    seen: list[str] = []
    targets: list[object] = []

    def collect(url: str, live_target: object = None) -> Artifacts:
        seen.append(url)
        targets.append(live_target)
        return _artifacts()

    Investigator(api, collect)(job)
    assert seen == ["https://from-db.example.com/"]
    # 실시간 화면은 이 사건·작업으로만 보낸다
    assert targets == [(str(job.case_id), str(job.job_id))]
    # 모든 API 호출에 같은 작업 ID를 붙인다(backend 멱등 처리의 기준)
    assert api.jobs and set(api.jobs) == {job.job_id}
    assert [k for k, _, _ in api.uploads] == ["screenshot", "dom_summary", "redirect_chain", "network_summary"]
    assert api.completed == [("collected", None)]


def test_skips_when_not_claimable() -> None:
    api = FakeApi(None)

    def collect(url: str, live_target: object = None) -> Artifacts:
        raise AssertionError("must not collect")

    Investigator(api, collect)(_job())
    assert api.uploads == [] and api.completed == []


def test_failed_collection_still_uploads_partial_evidence() -> None:
    job = _job()
    api = FakeApi(Target(case_id=job.case_id, url="https://x.example.com/"))
    partial = _artifacts(outcome="failed", reason="blocked_by_policy", dom_summary=None, screenshot=None)
    Investigator(api, lambda url, live_target=None: partial)(job)
    assert [k for k, _, _ in api.uploads] == ["redirect_chain", "network_summary"]
    assert api.completed == [("failed", "blocked_by_policy")]


def test_collector_crash_reports_code_only() -> None:
    job = _job()
    api = FakeApi(Target(case_id=job.case_id, url="https://x.example.com/"))

    def collect(url: str, live_target: object = None) -> Artifacts:
        raise RuntimeError("chromium crashed with /secret/path")

    Investigator(api, collect)(job)
    assert api.completed == [("failed", "collector_error")]


def test_api_failure_propagates_for_retry() -> None:
    job = _job()

    class BrokenApi(FakeApi):
        def upload_evidence(self, *a: object, **kw: object) -> dict:
            raise ConnectionError("backend down")

    api = BrokenApi(Target(case_id=job.case_id, url="https://x.example.com/"))
    with pytest.raises(ConnectionError):
        Investigator(api, lambda url, live_target=None: _artifacts())(job)
    assert api.completed == []


def test_evidence_json_is_utf8_and_sorted() -> None:
    files = dict((k, d) for k, d, _ in _artifacts(dom_summary={"title": "하늘은행", "a": 1}).files())
    assert json.loads(files["dom_summary"]) == {"title": "하늘은행", "a": 1}
    assert files["dom_summary"].startswith(b'{"a"')


def test_clean_text_strips_control_chars_and_non_strings() -> None:
    assert clean_text("a\x00b\x1bc\nd", 100) == "a b c\nd"
    assert clean_text({"not": "a string"}, 100) == ""
    assert len(clean_text("x" * 1000, 10)) == 10


def test_caching_guard_resolves_each_origin_once() -> None:
    calls: list[str] = []

    def resolver(host: str, port: int) -> list[str]:
        calls.append(host)
        return ["93.184.216.34"] if host == "ok.example.com" else ["10.0.0.1"]

    guard = CachingGuard(UrlGuard(resolver=resolver))
    guard.check("https://ok.example.com/a")
    guard.check("https://ok.example.com/b.js")
    for _ in range(2):
        with pytest.raises(Blocked):
            guard.check("https://bad.example.com/")
    assert calls == ["ok.example.com", "bad.example.com"]


@pytest.mark.parametrize("base", ["file:///etc", "ftp://backend", "backend:8000"])
def test_api_client_rejects_non_http_base(base: str) -> None:
    with pytest.raises(ValueError):
        ApiClient(base, "token")


def test_api_client_requires_token() -> None:
    with pytest.raises(ValueError):
        ApiClient("http://backend:8000", "")
