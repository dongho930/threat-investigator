"""Worker 전용 내부 API.

- /internal 경로는 nginx가 프록시하지 않으므로 콘솔(공개 네트워크)에서는 닿지 않는다.
  Worker와 backend만 연결된 `api` 네트워크에서만 호출된다.
- 서비스 토큰(Bearer)으로 인증한다. 사람 사용자의 인증·RBAC(4주차)와는 별개다.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Response, status

from app.api.deps import DbDep, FrameStoreDep, SettingsDep, StoreDep, read_limited_body, read_live_frame, require_worker
from app.db.models import EvidenceKind
from app.judging import service as judging
from app.schemas.evidence import (
    ClaimRequest,
    ClaimResult,
    CompleteRequest,
    CompleteResult,
    EvidenceOut,
    FeedImportRequest,
    FeedImportResponse,
)
from app.services import feed, investigation, live

router = APIRouter(prefix="/internal/v1", tags=["internal"], dependencies=[Depends(require_worker)])

COLLECTOR_VERSION_MAX = 50


@router.post("/cases/{case_id}/claim", response_model=ClaimResult)
def claim(case_id: uuid.UUID, body: ClaimRequest, db: DbDep, settings: SettingsDep) -> ClaimResult:
    case = investigation.claim_case(db, case_id, body.job_id, settings)
    # 조사 대상 URL은 큐 메시지가 아니라 여기서 DB 값으로 돌려준다(메시지 위·변조 대비).
    return ClaimResult(case_id=case.id, url=case.url_normalized, status=case.status)


@router.put("/cases/{case_id}/evidence/{kind}", response_model=EvidenceOut, status_code=status.HTTP_201_CREATED)
def upload_evidence(
    case_id: uuid.UUID,
    kind: EvidenceKind,
    db: DbDep,
    settings: SettingsDep,
    store: StoreDep,
    body: Annotated[bytes, Depends(read_limited_body)],
    x_job_id: Annotated[uuid.UUID, Header()],
    response: Response,
    content_type: Annotated[str, Header()] = "",
    x_collector_version: Annotated[str, Header(max_length=COLLECTOR_VERSION_MAX, pattern=r"^[\w./ -]+$")] = "unknown",
) -> EvidenceOut:
    evidence, created = investigation.add_evidence(
        db,
        store,
        settings,
        case_id=case_id,
        job_id=x_job_id,
        kind=kind,
        data=body,
        content_type=content_type,
        collector_version=x_collector_version,
    )
    if not created:
        # 같은 작업의 재업로드: 기존 증거를 돌려준다(새 파일을 만들지 않음).
        response.status_code = status.HTTP_200_OK
    return EvidenceOut.model_validate(evidence)


@router.post("/cases/{case_id}/live", status_code=status.HTTP_204_NO_CONTENT)
def live_frame(
    case_id: uuid.UUID,
    db: DbDep,
    settings: SettingsDep,
    frames: FrameStoreDep,
    body: Annotated[bytes, Depends(read_live_frame)],
    x_job_id: Annotated[uuid.UUID, Header()],
    content_type: Annotated[str, Header()] = "",
) -> Response:
    """조사 중인 브라우저 화면(JPEG) 한 장. 최신 것만 짧게 보관한다(증거 아님)."""
    live.put_frame(db, frames, settings, case_id=case_id, job_id=x_job_id, data=body, content_type=content_type)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/cases/{case_id}/complete", response_model=CompleteResult)
def complete(
    case_id: uuid.UUID, body: CompleteRequest, db: DbDep, store: StoreDep, settings: SettingsDep
) -> CompleteResult:
    case, changed = investigation.complete_case(
        db, case_id, body.job_id, body.outcome, body.reason, ai_enabled=settings.ai_model != "none"
    )
    if changed:
        # 수집 성공이면 증거로 규칙 판정, 실패면 '판단 불가(UNKNOWN)'를 기록한다(실패를 안전으로 두지 않음).
        judging.judge_case(db, store, case, body.job_id, collected=body.outcome is investigation.Outcome.COLLECTED)
    return CompleteResult(case_id=case.id, status=case.status, status_reason=case.status_reason)


@router.post("/feed/import", response_model=FeedImportResponse)
def import_feed(body: FeedImportRequest, db: DbDep, settings: SettingsDep) -> FeedImportResponse:
    """피드 수집기가 체크섬을 확인한 URL 목록을 등록한다. URL마다 정책 검사, 하루 신규 사건 수 제한."""
    urls = body.urls[: settings.feed_batch_max_items]
    result = feed.import_feed(db, settings, source=body.source, urls=urls)
    return FeedImportResponse(**result.__dict__)
