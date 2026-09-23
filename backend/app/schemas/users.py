import uuid

from pydantic import BaseModel, ConfigDict

from app.db.models import UserRole


class UserBrief(BaseModel):
    """배정 대상 선택용. 비밀번호 해시·활성 여부 등 다른 필드는 내보내지 않는다."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    role: UserRole


class UserList(BaseModel):
    items: list[UserBrief]
