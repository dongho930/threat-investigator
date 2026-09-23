"""비밀번호 해시(Argon2id).

- argon2-cffi 기본값(Argon2id, RFC 9106 저메모리 권장값)을 쓴다. 매개변수가 바뀌면 로그인 성공 때 새 해시로 바꾼다.
- 없는 계정으로 로그인해도 같은 시간이 걸리도록 더미 해시를 검증한다(계정 존재 여부 노출 방지).
"""

from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_LENGTH = 12
# Argon2 자체는 긴 입력도 받지만, 매우 긴 비밀번호로 CPU를 쓰게 하는 요청을 막는다.
MAX_LENGTH = 128

_hasher = PasswordHasher()


class WeakPasswordError(ValueError):
    pass


@lru_cache
def _dummy_hash() -> str:
    return _hasher.hash("dummy-password-for-timing-only")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    if stored_hash is None:
        try:
            _hasher.verify(_dummy_hash(), password)
        except VerificationError:
            pass
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)


def validate_new_password(password: str, username: str) -> None:
    """새 비밀번호 규칙: 12~128자, 아이디와 다를 것, 한 글자 반복 금지."""
    if not MIN_LENGTH <= len(password) <= MAX_LENGTH:
        raise WeakPasswordError(f"비밀번호는 {MIN_LENGTH}~{MAX_LENGTH}자여야 합니다.")
    if password.lower() == username.lower() or username.lower() in password.lower():
        raise WeakPasswordError("비밀번호에 아이디를 넣을 수 없습니다.")
    if len(set(password)) < 4:
        raise WeakPasswordError("같은 글자를 반복한 비밀번호는 쓸 수 없습니다.")
