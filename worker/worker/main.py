import logging
import os
import time

import redis

from worker.api_client import ApiClient
from worker.collector import Collector
from worker.config import WorkerSettings
from worker.consumer import Consumer, ConsumerConfig
from worker.investigate import Investigator
from worker.url_guard import ProxyCheck, UrlGuard


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = WorkerSettings()
    api = ApiClient(
        settings.api_base_url,
        settings.api_token,
        timeout_s=settings.api_timeout_s,
        collector_version=settings.collector_version,
    )
    # 프록시를 쓰면 목적지 판단(DNS·IP)은 프록시에 묻는다. Worker는 인터넷 DNS에 닿지 않는다.
    remote_check = ProxyCheck(settings.egress_proxy_url) if settings.egress_proxy_url else None
    guard = UrlGuard(
        host_allowlist=settings.host_allowlist, allowed_ports=settings.allowed_ports, remote_check=remote_check
    )
    logging.getLogger(__name__).info(
        "egress proxy=%s chromium sandbox=%s",
        "on" if remote_check else "off (local DNS check)",
        "on" if settings.chromium_sandbox else "OFF",
    )
    handler = Investigator(api, Collector(settings, guard))

    consumer_cfg = ConsumerConfig()
    # XREADGROUP BLOCK 동안 소켓이 먼저 끊기지 않도록 읽기 제한시간을 BLOCK보다 길게 둔다 (redis-py 8 기본값 5초).
    client = redis.Redis.from_url(
        os.environ["REDIS_URL"], decode_responses=True, socket_timeout=consumer_cfg.block_ms / 1000 + 5
    )
    consumer = Consumer(client, handler, consumer_cfg)
    consumer.ensure_group()
    logging.getLogger(__name__).info("worker started stream=%s group=%s", consumer.cfg.stream, consumer.cfg.group)
    while True:
        try:
            consumer.run_once()
        except (redis.ConnectionError, redis.TimeoutError):
            logging.getLogger(__name__).warning("redis unavailable, retrying")
            time.sleep(2)


if __name__ == "__main__":
    main()
