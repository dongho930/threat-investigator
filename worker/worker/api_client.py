"""backend 내부 API 클라이언트. Worker는 DB에 접근하지 않고 이 API로만 상태·증거를 기록한다."""

import json
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


class ApiError(Exception):
    def __init__(self, status: int, code: str) -> None:
        super().__init__(f"api error status={status} code={code}")
        self.status = status
        self.code = code


@dataclass(frozen=True)
class Target:
    case_id: uuid.UUID
    url: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """내부 API 응답의 리다이렉트는 따라가지 않는다(토큰이 다른 곳으로 새지 않게)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class ApiClient:
    def __init__(self, base_url: str, token: str, *, timeout_s: float = 15.0, collector_version: str = "") -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("API_BASE_URL must be an http(s) URL")
        if not token:
            raise ValueError("WORKER_API_TOKEN is required")
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.timeout_s = timeout_s
        self.collector_version = collector_version
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _request(
        self, method: str, path: str, body: bytes | None, content_type: str | None, job_id: uuid.UUID | None = None
    ) -> Any:
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        if job_id is not None:
            headers["X-Job-Id"] = str(job_id)
        if content_type:
            headers["Content-Type"] = content_type
        if self.collector_version:
            headers["X-Collector-Version"] = self.collector_version
        # base_url은 생성자에서 http(s)만 허용했으므로 file: 등 다른 스킴이 열릴 수 없다.
        req = urllib.request.Request(f"{self.base_url}{path}", data=body, method=method, headers=headers)  # noqa: S310
        try:
            with self._opener.open(req, timeout=self.timeout_s) as res:
                return json.loads(res.read(1_000_000) or b"null")
        except urllib.error.HTTPError as exc:
            try:
                code = str(json.loads(exc.read(10_000)).get("code", "http_error"))
            except (ValueError, AttributeError):
                code = "http_error"
            raise ApiError(exc.code, code) from None

    def claim(self, case_id: uuid.UUID, job_id: uuid.UUID) -> Target | None:
        """조사 대상 URL을 받는다. 끝난 사건이거나 더 최신 작업이 있으면(stale_job) None."""
        body = json.dumps({"job_id": str(job_id)}).encode()
        try:
            data = self._request("POST", f"/internal/v1/cases/{case_id}/claim", body, "application/json")
        except ApiError as exc:
            if exc.status in (404, 409):
                return None
            raise
        return Target(case_id=uuid.UUID(data["case_id"]), url=str(data["url"]))

    def upload_evidence(self, case_id: uuid.UUID, job_id: uuid.UUID, kind: str, data: bytes, content_type: str) -> dict:
        # 같은 작업의 재업로드는 backend가 기존 증거를 돌려준다(멱등).
        return self._request("PUT", f"/internal/v1/cases/{case_id}/evidence/{kind}", data, content_type, job_id)

    def complete(self, case_id: uuid.UUID, job_id: uuid.UUID, outcome: str, reason: str | None = None) -> dict:
        body = json.dumps({"job_id": str(job_id), "outcome": outcome, "reason": reason}).encode()
        return self._request("POST", f"/internal/v1/cases/{case_id}/complete", body, "application/json")
