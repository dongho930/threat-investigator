"""Chromium 샌드박스 설정이 조용히 풀리지 않도록 배포 설정과 seccomp 프로필을 검사한다."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "worker" / "seccomp" / "chromium.json"
CHROMIUM_CALLS = {"clone", "unshare", "setns", "chroot"}


def _profile() -> dict:
    return json.loads(PROFILE.read_text(encoding="utf-8"))


def test_profile_denies_by_default() -> None:
    assert _profile()["defaultAction"] == "SCMP_ACT_ERRNO"


def test_only_chromium_calls_added_unconditionally() -> None:
    rules = _profile()["syscalls"]
    extra = rules[-1]
    assert set(extra["names"]) == CHROMIUM_CALLS
    assert extra["action"] == "SCMP_ACT_ALLOW" and "args" not in extra and "includes" not in extra
    # 나머지 규칙에서는 네임스페이스·chroot 호출이 권한 조건 없이 허용되지 않는다(Docker 기본값 유지).
    for rule in rules[:-1]:
        if rule["action"] == "SCMP_ACT_ALLOW" and not rule.get("includes") and not rule.get("args"):
            assert not (set(rule["names"]) & CHROMIUM_CALLS), rule["names"]


def test_dangerous_calls_stay_blocked() -> None:
    allowed = set()
    for rule in _profile()["syscalls"]:
        if rule["action"] == "SCMP_ACT_ALLOW" and not rule.get("includes"):
            allowed |= set(rule["names"])
    for name in ("mount", "ptrace", "bpf", "kexec_load", "io_uring_setup", "open_by_handle_at"):
        assert name not in allowed, name


def test_compose_enables_sandbox_with_profile() -> None:
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    worker = compose.split("\n  worker:\n", 1)[1].split("\n  egress-proxy:\n", 1)[0]
    assert 'CHROMIUM_SANDBOX: "true"' in worker
    assert "seccomp=./worker/seccomp/chromium.json" in worker
    assert 'cap_drop: ["ALL"]' in compose and "<<: *hardening" in worker
