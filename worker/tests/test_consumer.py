import json
import uuid

import pytest

from worker.consumer import Consumer, ConsumerConfig, Outcome
from worker.messages import InvalidMessage, parse_job


class FakeRedis:
    def __init__(self, deliveries: int = 1) -> None:
        self.acked: list[str] = []
        self.added: list[tuple[str, dict[str, str]]] = []
        self.deliveries = deliveries

    def xack(self, stream: str, group: str, entry_id: str) -> int:
        self.acked.append(entry_id)
        return 1

    def xadd(self, stream: str, fields: dict[str, str], maxlen: int | None = None) -> str:
        self.added.append((stream, fields))
        return "1-0"

    def xpending_range(self, stream: str, group: str, min: str, max: str, count: int) -> list[dict]:
        return [{"message_id": min, "times_delivered": self.deliveries}]


def _fields(**overrides: object) -> dict[str, str]:
    payload = {"job_id": str(uuid.uuid4()), "case_id": str(uuid.uuid4()), "stage": "investigate", "attempt": 1}
    payload.update(overrides)
    return {"outbox_id": "1", "topic": "investigate", "payload": json.dumps(payload)}


CFG = ConsumerConfig(max_deliveries=3)


def test_success_acks() -> None:
    r = FakeRedis()
    seen = []
    assert Consumer(r, seen.append, CFG).process("1-0", _fields()) is Outcome.DONE
    assert r.acked == ["1-0"] and len(seen) == 1


def test_failure_leaves_pending_for_retry() -> None:
    r = FakeRedis(deliveries=1)

    def boom(job: object) -> None:
        raise RuntimeError("browser crashed")

    assert Consumer(r, boom, CFG).process("1-0", _fields()) is Outcome.RETRY
    assert r.acked == [] and r.added == []


def test_too_many_deliveries_goes_to_dead_letter() -> None:
    r = FakeRedis(deliveries=3)

    def boom(job: object) -> None:
        raise RuntimeError("still failing")

    assert Consumer(r, boom, CFG).process("1-0", _fields()) is Outcome.DEAD
    assert r.acked == ["1-0"]
    assert r.added[0][0] == "jobs:dead" and r.added[0][1]["reason"] == "max_deliveries"


@pytest.mark.parametrize(
    "fields",
    [
        {"payload": "not json"},
        {"payload": json.dumps({"job_id": "x"})},
        _fields(stage="rm -rf"),
        _fields(extra="field"),
        _fields(attempt=999),
        {"payload": "{" + " " * 5000 + "}"},
        {},
    ],
)
def test_invalid_messages_are_dead_lettered(fields: dict[str, str]) -> None:
    r = FakeRedis()
    handled = []
    assert Consumer(r, handled.append, CFG).process("9-0", fields) is Outcome.DEAD
    assert handled == [] and r.acked == ["9-0"]


def test_parse_job_rejects_pickle_like_payload() -> None:
    with pytest.raises(InvalidMessage):
        parse_job({"payload": "\x80\x04\x95"})


class FakeStreams(FakeRedis):
    """스트림별 대기 메시지를 흉내 낸다(우선순위 시험용)."""

    def __init__(self, queued: dict[str, list[tuple[str, dict[str, str]]]]) -> None:
        super().__init__()
        self.queued = queued
        self.read_calls: list[tuple[str, ...]] = []

    def xautoclaim(self, stream, group, consumer, min_idle, start_id="0-0", count=5):
        return ("0-0", [], [])

    def xreadgroup(self, group, consumer, streams, count=1, block=None):
        self.read_calls.append(tuple(streams))
        out = []
        for name in streams:
            if self.queued.get(name):
                out.append((name, [self.queued[name].pop(0)]))
        return out

    def xack(self, stream: str, group: str, entry_id: str) -> int:
        self.acked.append(f"{stream}:{entry_id}")
        return 1


PRIO = ConsumerConfig(stream="jobs:main", low_priority_stream="jobs:feed", max_deliveries=3)


def test_high_priority_stream_is_served_before_feed() -> None:
    r = FakeStreams({"jobs:main": [("1-0", _fields())], "jobs:feed": [("9-0", _fields()), ("9-1", _fields())]})
    seen: list[object] = []
    c = Consumer(r, seen.append, PRIO)
    c.run_once()
    assert r.acked == ["jobs:main:1-0"]  # 신고·수동 건이 먼저
    c.run_once()
    c.run_once()
    assert r.acked == ["jobs:main:1-0", "jobs:feed:9-0", "jobs:feed:9-1"]


def test_feed_waits_while_main_has_work() -> None:
    r = FakeStreams({"jobs:main": [("1-0", _fields()), ("1-1", _fields())], "jobs:feed": [("9-0", _fields())]})
    c = Consumer(r, lambda job: None, PRIO)
    c.run_once()
    c.run_once()
    assert r.acked == ["jobs:main:1-0", "jobs:main:1-1"]
    # 두 번 모두 첫 비차단 읽기에서 주 스트림만 읽었다
    assert r.read_calls == [("jobs:main",), ("jobs:main",)]


def test_dead_letter_records_source_stream() -> None:
    r = FakeStreams({})
    Consumer(r, lambda job: None, PRIO).process("5-0", {"payload": "not json"}, "jobs:feed")
    assert r.added[0][1]["source_stream"] == "jobs:feed" and r.acked == ["jobs:feed:5-0"]
