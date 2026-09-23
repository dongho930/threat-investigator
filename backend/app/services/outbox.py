"""Outbox relay: DB에 기록된 작업 이벤트를 Redis Streams로 발행한다.

relay가 발행 직후 죽으면 같은 이벤트가 다시 발행될 수 있다(최소 1회 전달).
같은 job_id가 여러 번 전달돼도 backend가 작업 단위로 멱등 처리한다(app/services/investigation.py).
relay는 주기적으로 스위퍼(app/services/sweeper.py)도 실행해 멈춘 사건을 다시 발행한다.
"""

import json
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.db.models import OutboxEvent

logger = logging.getLogger(__name__)


class StreamClient(Protocol):
    def xadd(self, name: str, fields: dict[str, str], maxlen: int | None = ..., approximate: bool = ...) -> object: ...


def publish_pending(db: Session, client: StreamClient, *, stream: str, batch_size: int = 50) -> int:
    events = db.scalars(
        select(OutboxEvent)
        .where(OutboxEvent.published_at.is_(None))
        .order_by(OutboxEvent.id)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
    ).all()
    for event in events:
        message = {"outbox_id": str(event.id), "topic": event.topic, "payload": json.dumps(event.payload)}
        client.xadd(stream, message, maxlen=100_000, approximate=True)
        event.published_at = datetime.now(UTC)
    db.commit()
    return len(events)


def run_forever(
    session_factory: sessionmaker[Session],
    client: StreamClient,
    *,
    stream: str,
    sweep: Callable[[Session], object] | None = None,
    sweep_interval_s: float = 30.0,
) -> None:
    last_sweep = 0.0
    while True:
        try:
            if sweep is not None and time.monotonic() - last_sweep >= sweep_interval_s:
                last_sweep = time.monotonic()
                with session_factory() as db:
                    sweep(db)
            with session_factory() as db:
                published = publish_pending(db, client, stream=stream)
            if published:
                logger.info("outbox published=%d", published)
                continue
        except Exception:
            logger.exception("outbox relay error")
        time.sleep(1.0)


if __name__ == "__main__":
    import redis

    from app.core.config import get_settings
    from app.core.logging import configure_logging
    from app.db.session import get_sessionmaker
    from app.services.sweeper import sweep as sweep_cases

    configure_logging()
    settings = get_settings()
    run_forever(
        get_sessionmaker(),
        redis.Redis.from_url(settings.redis_url),
        stream=settings.job_stream,
        sweep=lambda db: sweep_cases(db, settings),
        sweep_interval_s=settings.sweep_interval_seconds,
    )
