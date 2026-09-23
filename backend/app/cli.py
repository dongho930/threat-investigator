"""계정 관리 CLI. 계정 생성·비활성화·비밀번호 초기화는 콘솔 API로 열지 않고 서버에서만 한다.

    docker compose exec backend python -m app.cli create-user --username kim --role investigator
    docker compose exec backend python -m app.cli set-active --username kim --inactive
    docker compose exec backend python -m app.cli reset-password --username kim

비밀번호는 명령줄 인자로 받지 않는다(셸 기록·프로세스 목록 노출 방지). 터미널에서 두 번 입력하거나,
자동화할 때는 --password-stdin으로 표준 입력 한 줄을 읽는다.
"""

import argparse
import getpass
import re
import sys

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import AuditLog, User, UserRole
from app.db.session import get_sessionmaker
from app.security import passwords
from app.services.auth import normalize_username, revoke_user_sessions

USERNAME = re.compile(r"^[a-z0-9._-]{3,32}$")


class CliError(Exception):
    pass


def _read_password(username: str, from_stdin: bool) -> str:
    if from_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("새 비밀번호: ")
        if getpass.getpass("한 번 더: ") != password:
            raise CliError("두 비밀번호가 다릅니다.")
    try:
        passwords.validate_new_password(password, username)
    except passwords.WeakPasswordError as exc:
        raise CliError(str(exc)) from exc
    return password


def _get_user(db: Session, username: str) -> User:
    user = db.scalar(select(User).where(User.username == normalize_username(username)))
    if user is None:
        raise CliError("그런 계정이 없습니다.")
    return user


def create_user(db: Session, username: str, role: str, password: str) -> User:
    name = normalize_username(username)
    if not USERNAME.match(name):
        raise CliError("아이디는 영문 소문자·숫자·._- 3~32자여야 합니다.")
    user = User(username=name, password_hash=passwords.hash_password(password), role=UserRole(role))
    db.add(user)
    try:
        db.flush()  # 아이디 중복은 여기서 UNIQUE 제약으로 걸린다
        db.add(
            AuditLog(
                actor="cli", action="user.create", target_type="user", target_id=str(user.id), after={"role": role}
            )
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise CliError("이미 있는 아이디입니다.") from exc
    return user


def set_active(db: Session, username: str, active: bool) -> User:
    user = _get_user(db, username)
    user.is_active = active
    if not active:
        revoke_user_sessions(db, user.id)  # 비활성화 즉시 로그인 중인 세션도 끊는다
    db.add(
        AuditLog(
            actor="cli", action="user.set_active", target_type="user", target_id=str(user.id), after={"active": active}
        )
    )
    db.commit()
    return user


def reset_password(db: Session, username: str, password: str) -> User:
    user = _get_user(db, username)
    user.password_hash = passwords.hash_password(password)
    revoke_user_sessions(db, user.id)
    db.add(AuditLog(actor="cli", action="user.reset_password", target_type="user", target_id=str(user.id)))
    db.commit()
    return user


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="콘솔 계정 관리")
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create-user", help="계정 만들기")
    p_create.add_argument("--username", required=True)
    p_create.add_argument("--role", required=True, choices=[r.value for r in UserRole])
    p_create.add_argument("--password-stdin", action="store_true")

    p_active = sub.add_parser("set-active", help="계정 활성·비활성")
    p_active.add_argument("--username", required=True)
    group = p_active.add_mutually_exclusive_group(required=True)
    group.add_argument("--active", dest="active", action="store_true")
    group.add_argument("--inactive", dest="active", action="store_false")

    p_reset = sub.add_parser("reset-password", help="비밀번호 초기화(로그인 중인 세션도 끊음)")
    p_reset.add_argument("--username", required=True)
    p_reset.add_argument("--password-stdin", action="store_true")

    args = parser.parse_args(argv)
    try:
        with get_sessionmaker()() as db:
            if args.command == "create-user":
                user = create_user(db, args.username, args.role, _read_password(args.username, args.password_stdin))
                print(f"계정을 만들었습니다: {user.username} ({user.role.value})")
            elif args.command == "set-active":
                user = set_active(db, args.username, args.active)
                print(f"{user.username}: {'활성' if user.is_active else '비활성(세션 종료)'}")
            else:
                user = reset_password(db, args.username, _read_password(args.username, args.password_stdin))
                print(f"{user.username}: 비밀번호를 바꾸고 로그인 중인 세션을 끊었습니다.")
    except CliError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
