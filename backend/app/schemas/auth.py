import uuid

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import UserRole
from app.security.passwords import MAX_LENGTH


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=MAX_LENGTH)


class MeOut(BaseModel):
    """로그인 사용자 정보와 이 세션의 CSRF 토큰. 콘솔은 상태 변경 요청에 X-CSRF-Token으로 되돌려 보낸다."""

    id: uuid.UUID
    username: str
    role: UserRole
    permissions: list[str]
    csrf_token: str
