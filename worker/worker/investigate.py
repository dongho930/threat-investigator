"""격리 브라우저 조사 (2주차에 구현).

구현할 때 지킬 것:
- 조사 대상 URL은 메시지가 아니라 API에서 case_id로 다시 조회한다(메시지 위·변조 대비).
- 요청마다 실제 연결 IP를 다시 검사한다(backend의 url_policy.is_ip_allowed 규칙과 동일하게).
- 다운로드·새 창·Service Worker·외부 프로토콜 차단, 시간·크기·리다이렉트 횟수 제한.
- 쿠키·인증 헤더·폼 입력값은 저장하지 않는다. 증거 파일 이름은 서버가 만든 UUID만 쓴다.
"""

import logging

from worker.messages import JobMessage

logger = logging.getLogger(__name__)


def investigate(job: JobMessage) -> None:
    logger.info(
        "received job=%s case=%s stage=%s (investigation not implemented yet)", job.job_id, job.case_id, job.stage
    )
