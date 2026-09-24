"""실시간 조사 화면 전송. 격리 수집 자식 프로세스 안에서 만들어 쓴다.

- 화면(JPEG)은 backend 내부 API로만 보낸다. 사건의 현재 작업이 아니거나 조사가 끝났으면(409) 더 보내지 않는다.
- 전송 실패는 조사를 멈추지 않는다(실시간 화면은 보조 기능이다. 증거는 녹화·스크린샷으로 남는다).
"""

import logging
import time
import uuid
from collections.abc import Callable

from worker.api_client import ApiClient, ApiError
from worker.config import WorkerSettings

logger = logging.getLogger(__name__)

LiveSink = Callable[[bytes], None]
LiveTarget = tuple[str, str]  # (case_id, job_id)


def make_live_sink(target: LiveTarget, settings: WorkerSettings, api: ApiClient | None = None) -> LiveSink:
    case_id, job_id = uuid.UUID(target[0]), uuid.UUID(target[1])
    client = api or ApiClient(
        settings.api_base_url, settings.api_token, timeout_s=3, collector_version=settings.collector_version
    )
    state = {"stopped": False, "last": 0.0}

    def send(frame: bytes) -> None:
        now = time.monotonic()
        if state["stopped"] or now - state["last"] < settings.live_min_interval_s:
            return
        state["last"] = now
        try:
            client.post_live_frame(case_id, job_id, frame)
        except ApiError as exc:
            state["stopped"] = True
            logger.info("live view stopped case=%s status=%s", case_id, exc.status)
        except OSError:
            state["stopped"] = True
            logger.warning("live view unavailable case=%s", case_id)

    return send
