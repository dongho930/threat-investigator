"""조사 작업 처리기: 대상 조회 → 격리 브라우저 수집 → 증거 업로드 → 결과 보고.

- 조사 대상 URL은 큐 메시지가 아니라 API에서 case_id로 다시 받는다(메시지 위·변조 대비).
- 대상 사이트 때문에 생긴 실패(차단·시간초과·연결 오류)는 사유 코드와 함께 "failed"로 보고하고 재시도하지 않는다.
- 내부 API 호출 실패는 예외를 그대로 올려 소비자가 재시도하게 한다.
"""

import logging
from collections.abc import Callable
from typing import Protocol

from worker.api_client import Target
from worker.collector import Artifacts
from worker.messages import JobMessage

logger = logging.getLogger(__name__)


class Api(Protocol):
    def claim(self, case_id: object) -> Target | None: ...
    def upload_evidence(self, case_id: object, kind: str, data: bytes, content_type: str) -> dict: ...
    def complete(self, case_id: object, outcome: str, reason: str | None = None) -> dict: ...


Collect = Callable[[str], Artifacts]


class Investigator:
    def __init__(self, api: Api, collect: Collect) -> None:
        self.api = api
        self.collect = collect

    def __call__(self, job: JobMessage) -> None:
        target = self.api.claim(job.case_id)
        if target is None:
            logger.info("skip job=%s case=%s (not claimable)", job.job_id, job.case_id)
            return

        try:
            artifacts = self.collect(target.url)
        except Exception:
            # 수집기 자체 오류는 원문 메시지를 API로 보내지 않고 정해진 사유 코드만 보고한다.
            logger.exception("collector crashed case=%s", job.case_id)
            self.api.complete(job.case_id, "failed", "collector_error")
            return

        for kind, data, content_type in artifacts.files():
            self.api.upload_evidence(job.case_id, kind, data, content_type)
        self.api.complete(job.case_id, artifacts.outcome, artifacts.reason)
        logger.info(
            "investigated case=%s outcome=%s reason=%s evidence=%d",
            job.case_id,
            artifacts.outcome,
            artifacts.reason,
            len(artifacts.files()),
        )
