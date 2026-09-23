import uuid

from fastapi import APIRouter, Response

from app.api.deps import DbDep, StoreDep
from app.db.models import EvidenceKind
from app.schemas.evidence import EvidenceList, EvidenceOut
from app.services import investigation

# TODO(4주차): 인증·RBAC·사건 단위 접근 확인(IDOR) 추가
router = APIRouter(prefix="/api/v1/cases/{case_id}/evidence", tags=["evidence"])

MEDIA_TYPES = {EvidenceKind.SCREENSHOT: ("image/png", "png")}
DEFAULT_MEDIA = ("application/json", "json")


@router.get("", response_model=EvidenceList)
def list_evidence(case_id: uuid.UUID, db: DbDep) -> EvidenceList:
    return EvidenceList(items=[EvidenceOut.model_validate(e) for e in investigation.list_evidence(db, case_id)])


@router.get("/{evidence_id}/content")
def get_evidence_content(case_id: uuid.UUID, evidence_id: uuid.UUID, db: DbDep, store: StoreDep) -> Response:
    evidence, data = investigation.read_evidence(db, store, case_id=case_id, evidence_id=evidence_id)
    media_type, ext = MEDIA_TYPES.get(evidence.kind, DEFAULT_MEDIA)
    # Content-Type은 저장 시 검증한 종류로 고정한다. 파일명은 서버가 만든 ID만 쓴다.
    return Response(
        content=data,
        media_type=media_type,
        headers={
            "Content-Disposition": f'inline; filename="{evidence.id}.{ext}"',
            "X-Evidence-SHA256": evidence.sha256,
        },
    )
