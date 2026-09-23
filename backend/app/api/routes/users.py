from fastapi import APIRouter, Depends
from sqlalchemy import select

from app.api.deps import DbDep, require
from app.db.models import User, UserRole
from app.schemas.users import UserBrief, UserList
from app.security.rbac import Permission

router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.get("", response_model=UserList, dependencies=[Depends(require(Permission.USER_LIST))])
def list_users(db: DbDep, role: UserRole | None = None) -> UserList:
    """배정 대상 선택용 활성 사용자 목록(검토자·관리자). 계정 생성·변경은 서버 CLI로만 한다."""
    query = select(User).where(User.is_active.is_(True)).order_by(User.username)
    if role is not None:
        query = query.where(User.role == role)
    return UserList(items=[UserBrief.model_validate(u) for u in db.scalars(query).all()])
