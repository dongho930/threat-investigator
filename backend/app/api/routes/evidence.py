import uuid

from fastapi import APIRouter, Depends, Response

from app.api.deps import AccessibleCase, DbDep, StoreDep, require
from app.db.models import EvidenceKind
from app.schemas.evidence import EvidenceList, EvidenceOut
from app.security.rbac import Permission
from app.services import investigation

# 증거는 사건 단위 접근 확인(AccessibleCase)을 거친 뒤, 그 사건에 속한 것만 돌려준다(IDOR 방지).
router = APIRouter(
    prefix="/api/v1/cases/{case_id}/evidence",
    tags=["evidence"],
    dependencies=[Depends(require(Permission.CASE_READ))],
)

MEDIA_TYPES = {EvidenceKind.SCREENSHOT: ("image/png", "png")}
DEFAULT_MEDIA = ("application/json", "json")


@router.get("", response_model=EvidenceList)
def list_evidence(case: AccessibleCase, db: DbDep) -> EvidenceList:
    return EvidenceList(items=[EvidenceOut.model_validate(e) for e in investigation.list_evidence(db, case.id)])


@router.get("/{evidence_id}/content")
def get_evidence_content(case: AccessibleCase, evidence_id: uuid.UUID, db: DbDep, store: StoreDep) -> Response:
    evidence, data = investigation.read_evidence(db, store, case_id=case.id, evidence_id=evidence_id)
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
