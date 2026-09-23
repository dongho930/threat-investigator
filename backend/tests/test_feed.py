"""위협정보 피드 자동 탐색 등록 시험."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import get_settings
from app.db.models import AuditLog, Case, CaseSource, OutboxEvent
from app.services.cases import FEED_TOPIC, INVESTIGATE_TOPIC
from app.services.outbox import publish_pending
from app.services.sweeper import sweep
from tests.conftest import WORKER_TOKEN

AUTH = {"Authorization": f"Bearer {WORKER_TOKEN}"}


def _import(client: TestClient, urls: list[str], source: str = "phishing.database", headers=AUTH):
    return client.post("/internal/v1/feed/import", headers=headers, json={"source": source, "urls": urls})


def test_feed_import_creates_low_priority_cases(client: TestClient) -> None:
    res = _import(
        client,
        [
            "https://feed-a.example.com/login",
            "https://feed-a.example.com/login#dup",
            "http://169.254.169.254/latest/meta-data/",
            "javascript:alert(1)",
            "https://feed-b.example.org/",
        ],
    )
    assert res.status_code == 200
    assert res.json() == {"received": 5, "created": 2, "duplicate": 1, "rejected": 2, "capped": 0}
    with client.app.state.session_factory() as db:
        cases = db.scalars(select(Case)).all()
        events = db.scalars(select(OutboxEvent)).all()
        audit = db.scalars(select(AuditLog).where(AuditLog.action == "feed.import")).one()
    assert {c.source for c in cases} == {CaseSource.FEED} and {c.source_ref for c in cases} == {"phishing.database"}
    assert {e.topic for e in events} == {FEED_TOPIC}
    assert audit.actor == "feed-collector" and audit.after["created"] == 2


def test_manual_and_report_cases_stay_high_priority(client: TestClient) -> None:
    client.post("/api/v1/cases", json={"url": "https://manual.example.com/"})
    with client.app.state.session_factory() as db:
        assert db.scalars(select(OutboxEvent)).one().topic == INVESTIGATE_TOPIC


def test_daily_cap_limits_new_cases(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(get_settings(), "feed_max_new_cases_per_day", 2)
    first = _import(client, [f"https://cap{i}.example.com/" for i in range(3)]).json()
    assert (first["created"], first["capped"]) == (2, 1)
    second = _import(client, ["https://cap9.example.com/"]).json()
    assert (second["created"], second["capped"]) == (0, 1)


def test_feed_import_requires_worker_token_and_valid_body(client: TestClient) -> None:
    assert _import(client, ["https://x.example.com/"], headers={}).status_code == 401
    assert _import(client, ["https://x.example.com/"], source="Bad Source!").status_code == 422
    assert _import(client, [f"https://{i}.example.com/" for i in range(501)]).status_code == 422


def test_outbox_routes_feed_topic_to_feed_stream(client: TestClient) -> None:
    client.post("/api/v1/cases", json={"url": "https://route-manual.example.com/"})
    _import(client, ["https://route-feed.example.com/"])

    class Stream:
        def __init__(self) -> None:
            self.sent: list[tuple[str, str]] = []

        def xadd(self, name, fields, maxlen=None, approximate=True):
            self.sent.append((name, fields["topic"]))

    stream = Stream()
    with client.app.state.session_factory() as db:
        assert publish_pending(db, stream, stream="jobs:main", topic_streams={FEED_TOPIC: "jobs:feed"}) == 2
    assert sorted(stream.sent) == [("jobs:feed", FEED_TOPIC), ("jobs:main", INVESTIGATE_TOPIC)]


def test_sweeper_requeues_feed_case_on_feed_topic(client: TestClient) -> None:
    _import(client, ["https://requeue-feed.example.com/"])
    with client.app.state.session_factory() as db:
        for e in db.scalars(select(OutboxEvent)):
            e.published_at = datetime.now(UTC)
        db.commit()
        later = datetime.now(UTC) + timedelta(seconds=get_settings().queued_stale_seconds + 1)
        assert sweep(db, get_settings(), now=later)["requeued"] == 1
        topics = [e.topic for e in db.scalars(select(OutboxEvent).order_by(OutboxEvent.id))]
    assert topics == [FEED_TOPIC, FEED_TOPIC]


@pytest.mark.parametrize("source", ["phishing.database", "kisa-2023", "a"])
def test_source_name_pattern_accepts_simple_names(client: TestClient, source: str) -> None:
    assert _import(client, [], source=source).status_code == 200
