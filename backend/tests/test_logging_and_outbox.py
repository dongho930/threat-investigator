import json

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.logging import redact_url, safe_log_value
from app.db.models import Base, OutboxEvent
from app.services.outbox import publish_pending


def test_safe_log_value_strips_newlines() -> None:
    assert "\n" not in safe_log_value("a\nFAKE LOG LINE\r\nb")
    assert len(safe_log_value("x" * 10_000)) <= 501


def test_redact_url_masks_query_values() -> None:
    out = redact_url("https://ex.com/p?token=SECRET&id=1")
    assert "SECRET" not in out
    assert "token=%2A%2A%2A" in out


class FakeStream:
    def __init__(self) -> None:
        self.messages: list[tuple[str, dict[str, str]]] = []

    def xadd(self, name: str, fields: dict[str, str], maxlen: int | None = None, approximate: bool = True) -> str:
        self.messages.append((name, fields))
        return f"{len(self.messages)}-0"


def test_publish_pending_marks_published_once() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        db.add(OutboxEvent(topic="investigate", payload={"case_id": "c1"}))
        db.commit()

    stream = FakeStream()
    with factory() as db:
        assert publish_pending(db, stream, stream="jobs") == 1
    with factory() as db:
        assert publish_pending(db, stream, stream="jobs") == 0
        assert db.scalars(select(OutboxEvent)).one().published_at is not None

    name, fields = stream.messages[0]
    assert name == "jobs"
    assert json.loads(fields["payload"]) == {"case_id": "c1"}
