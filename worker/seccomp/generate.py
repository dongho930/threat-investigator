"""Chromium 샌드박스용 seccomp 프로필 생성기.

Docker 기본 프로필(moby/profiles, 커밋 고정)을 그대로 두고, Chromium의 네임스페이스 샌드박스에 필요한
시스템 콜 4개만 조건 없이 허용하는 규칙을 하나 덧붙인다.

- clone / unshare : 렌더러 프로세스를 새 user·pid·net 네임스페이스에 가둔다.
- setns          : 샌드박스 헬퍼가 네임스페이스를 옮긴다.
- chroot         : 새 user 네임스페이스 안에서 빈 디렉터리로 루트를 바꾼다.

Docker 기본 프로필은 이 호출들을 CAP_SYS_ADMIN·CAP_SYS_CHROOT가 있을 때만 허용하는데, 우리는 컨테이너에서
모든 권한을 뺀다(cap_drop: ALL). 권한을 되돌리는 대신 이 호출만 허용하고, 실제 권한 확인은 커널에 맡긴다
(네임스페이스 밖에서는 권한이 없어 여전히 실패한다). 그 밖의 규칙(io_uring 차단 등)은 기본 프로필과 같다.

실행: python seccomp/generate.py  → seccomp/chromium.json 을 다시 만든다.
"""

import json
import urllib.request
from pathlib import Path

MOBY_COMMIT = "65adc7e022c97f55e45c054ff012988027733b87"  # 2026-08-25
SOURCE = f"https://raw.githubusercontent.com/moby/profiles/{MOBY_COMMIT}/seccomp/default.json"
CHROMIUM_RULE = {
    "names": ["clone", "unshare", "setns", "chroot"],
    "action": "SCMP_ACT_ALLOW",
    "comment": "Chromium namespace sandbox (threat-investigator worker)",
}


def build(default_profile: dict) -> dict:
    profile = json.loads(json.dumps(default_profile))
    profile["syscalls"].append(dict(CHROMIUM_RULE))
    return profile


def main() -> None:
    with urllib.request.urlopen(SOURCE, timeout=30) as res:  # noqa: S310 - 고정된 https URL
        default_profile = json.load(res)
    out = Path(__file__).with_name("chromium.json")
    # OS와 관계없이 같은 파일이 나오도록 줄바꿈을 LF로 고정한다.
    out.write_text(json.dumps(build(default_profile), indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {out} from moby/profiles@{MOBY_COMMIT[:12]}")


if __name__ == "__main__":
    main()
