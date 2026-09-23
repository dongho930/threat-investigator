import json
import os
from dataclasses import dataclass, field


def _json_list(name: str) -> list:
    raw = os.getenv(name, "").strip()
    return json.loads(raw) if raw else []


@dataclass(frozen=True)
class WorkerSettings:
    api_base_url: str = field(default_factory=lambda: os.getenv("API_BASE_URL", "http://backend:8000"))
    api_token: str = field(default_factory=lambda: os.getenv("WORKER_API_TOKEN", ""))
    api_timeout_s: float = 15.0

    # backend의 URL_HOST_ALLOWLIST와 같은 값을 쓴다(개발용 testsites만).
    host_allowlist: frozenset[str] = field(
        default_factory=lambda: frozenset(h.lower() for h in _json_list("URL_HOST_ALLOWLIST"))
    )
    allowed_ports: frozenset[int] = frozenset({80, 443, 8080, 8443})

    # 자원 제한
    navigation_timeout_ms: int = 15_000
    settle_ms: int = 2_500  # 지연 렌더링(setTimeout 등)을 기다리는 시간
    max_redirects: int = 10
    max_requests: int = 200
    max_text_chars: int = 5_000
    max_forms: int = 20
    max_hosts: int = 50
    viewport: tuple[int, int] = (1280, 800)

    # 송신 프록시. 설정하면 브라우저의 모든 요청과 목적지 검사가 이 프록시를 거친다(컨테이너 배포에서는 필수).
    egress_proxy_url: str | None = field(default_factory=lambda: os.getenv("EGRESS_PROXY_URL") or None)

    # Playwright 기본값은 샌드박스 꺼짐이므로 명시적으로 켠다. 컨테이너에서는 seccomp 프로필
    # (worker/seccomp/chromium.json)이 있어야 user namespace를 만들 수 있다. CI 러너처럼 막힌 환경에서만 끈다.
    chromium_sandbox: bool = field(
        default_factory=lambda: os.getenv("CHROMIUM_SANDBOX", "true").strip().lower() not in ("0", "false", "no")
    )

    collector_version: str = "worker/0.2.0 playwright/1.63.0"
