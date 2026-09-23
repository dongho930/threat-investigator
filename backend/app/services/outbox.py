"""Outbox relay: DB에 기록된 작업 이벤트를 Redis Streams로 발행한다.

relay가 발행 직후 죽으면 같은 이벤트가 다시 발행될 수 있다(최소 1회 전달).
따라서 Worker는 job_id / case_id+stage 기준으로 중복 실행을 막아야 한다(3주차).
"""

import json
import logging
import time
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


def run_forever(session_factory: sessionmaker[Session], client: StreamClient, *, stream: str) -> None:
    while True:
        try:
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

    configure_logging()
    settings = get_settings()
    run_forever(get_sessionmaker(), redis.Redis.from_url(settings.redis_url), stream=settings.job_stream)
