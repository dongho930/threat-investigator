import asyncio
import json
import logging
import os

from egress_proxy.policy import EgressPolicy
from egress_proxy.server import EgressProxy, serve


def _json_list(name: str) -> list:
    raw = os.getenv(name, "").strip()
    return json.loads(raw) if raw else []


async def run() -> None:
    policy = EgressPolicy(
        allowed_ports=frozenset(int(p) for p in (_json_list("EGRESS_ALLOWED_PORTS") or [80, 443, 8080, 8443])),
        # 개발용 시험 페이지(testsites)만 넣는다. 운영에서는 비워 둔다.
        host_allowlist=frozenset(_json_list("EGRESS_HOST_ALLOWLIST")),
    )
    proxy = EgressProxy(policy, max_connections=int(os.getenv("EGRESS_MAX_CONNECTIONS", "200")))
    # 컨테이너 내부 네트워크(sandbox)에서만 접근하도록 compose에서 포트를 공개하지 않는다.
    server = await serve(proxy, os.getenv("EGRESS_BIND", "0.0.0.0"), int(os.getenv("EGRESS_PORT", "3128")))  # noqa: S104  # nosec B104
    logging.getLogger(__name__).info("egress proxy listening allowlist=%s", sorted(policy.host_allowlist))
    async with server:
        await server.serve_forever()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(run())


if __name__ == "__main__":
    main()
