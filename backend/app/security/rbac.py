"""역할별 권한(RBAC)과 사건 단위 접근 규칙(IDOR 방지).

권한 확인은 모두 서버에서 한다. 콘솔이 버튼을 숨기는 것은 편의일 뿐이고, 판단 근거는 이 파일 하나다.

| 역할 | 할 수 있는 일 |
|---|---|
| 조사자(investigator) | URL 등록, 신고 CSV 등록, **자기가 등록했거나 배정받은 사건**만 조회 |
| 검토자(reviewer) | 모든 사건 조회, 조사자 배정, 판정 확정(자기가 등록한 사건은 제외) |
| 관리자(admin) | 위 권한 전부 |

계정 생성·비활성화·비밀번호 초기화는 API로 열지 않고 서버 CLI(`python -m app.cli`)로만 한다(공격 표면 축소).
"""

import enum
import uuid

from sqlalchemy import ColumnElement, false, or_, true

from app.db.models import Case, User, UserRole


class Permission(enum.StrEnum):
    CASE_CREATE = "case:create"
    CASE_READ = "case:read"
    CASE_READ_ALL = "case:read_all"
    CASE_ASSIGN = "case:assign"
    CASE_REVIEW = "case:review"
    REPORT_IMPORT = "report:import"
    USER_LIST = "user:list"


ROLE_PERMISSIONS: dict[UserRole, frozenset[Permission]] = {
    UserRole.INVESTIGATOR: frozenset({Permission.CASE_CREATE, Permission.CASE_READ, Permission.REPORT_IMPORT}),
    UserRole.REVIEWER: frozenset(
        {
            Permission.CASE_READ,
            Permission.CASE_READ_ALL,
            Permission.CASE_ASSIGN,
            Permission.CASE_REVIEW,
            Permission.USER_LIST,
        }
    ),
    UserRole.ADMIN: frozenset(Permission),
}


def permissions_of(user: User) -> frozenset[Permission]:
    return ROLE_PERMISSIONS.get(user.role, frozenset())


def has_permission(user: User, permission: Permission) -> bool:
    return permission in permissions_of(user)


def can_access_case(user: User, case: Case) -> bool:
    if has_permission(user, Permission.CASE_READ_ALL):
        return True
    if not has_permission(user, Permission.CASE_READ):
        return False
    return user.id in (case.created_by, case.assignee_id)


def case_visibility_filter(user: User) -> ColumnElement[bool]:
    """사건 목록 쿼리에 붙이는 조건. can_access_case와 같은 규칙이어야 한다."""
    if has_permission(user, Permission.CASE_READ_ALL):
        return true()
    if not has_permission(user, Permission.CASE_READ):
        return false()
    uid: uuid.UUID = user.id
    return or_(Case.created_by == uid, Case.assignee_id == uid)
