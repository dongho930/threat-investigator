"""Redis Streams 소비자.

- 성공했을 때만 ACK한다. 실패한 메시지는 대기 목록(PEL)에 남고, 일정 시간이 지나면 XAUTOCLAIM으로 회수해 재시도한다.
- 스키마가 틀린 메시지나 재시도 한도를 넘은 메시지는 dead-letter 스트림으로 옮기고 ACK한다.
"""

import logging
import os
import socket
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from redis.exceptions import ResponseError

from worker.messages import InvalidMessage, JobMessage, parse_job

logger = logging.getLogger(__name__)


class Outcome(StrEnum):
    DONE = "done"
    RETRY = "retry"
    DEAD = "dead"


@dataclass(frozen=True)
class ConsumerConfig:
    stream: str = os.getenv("JOB_STREAM", "jobs:investigate")
    # 피드로 자동 탐색한 작업은 낮은 우선순위 스트림에서 받는다. 비우면 한 스트림만 쓴다.
    low_priority_stream: str | None = os.getenv("FEED_JOB_STREAM", "jobs:investigate:feed") or None
    group: str = os.getenv("JOB_GROUP", "investigators")
    consumer: str = os.getenv("WORKER_NAME", socket.gethostname())
    dead_letter_stream: str = os.getenv("DEAD_LETTER_STREAM", "jobs:dead")
    max_deliveries: int = int(os.getenv("MAX_DELIVERIES", "5"))
    min_idle_ms: int = int(os.getenv("RECLAIM_IDLE_MS", "60000"))
    block_ms: int = 5000

    @property
    def streams(self) -> tuple[str, ...]:
        """우선순위가 높은 순서."""
        return (self.stream, self.low_priority_stream) if self.low_priority_stream else (self.stream,)


Handler = Callable[[JobMessage], None]


class Consumer:
    def __init__(self, client: Any, handler: Handler, config: ConsumerConfig | None = None) -> None:
        self.r = client
        self.handler = handler
        self.cfg = config or ConsumerConfig()

    def ensure_group(self) -> None:
        for stream in self.cfg.streams:
            try:
                self.r.xgroup_create(stream, self.cfg.group, id="0", mkstream=True)
            except ResponseError as exc:
                if "BUSYGROUP" not in str(exc):
                    raise

    def _dead_letter(self, stream: str, entry_id: str, fields: dict[str, str], reason: str) -> None:
        self.r.xadd(
            self.cfg.dead_letter_stream,
            {"source_stream": stream, "source_id": entry_id, "reason": reason, **fields},
            maxlen=10_000,
        )
        self.r.xack(stream, self.cfg.group, entry_id)

    def _deliveries(self, stream: str, entry_id: str) -> int:
        pending = self.r.xpending_range(stream, self.cfg.group, min=entry_id, max=entry_id, count=1)
        return int(pending[0]["times_delivered"]) if pending else 1

    def process(self, entry_id: str, fields: dict[str, str], stream: str | None = None) -> Outcome:
        stream = stream or self.cfg.stream
        try:
            job = parse_job(fields)
        except InvalidMessage as exc:
            logger.warning("invalid message id=%s reason=%s", entry_id, exc)
            self._dead_letter(stream, entry_id, fields, "invalid_message")
            return Outcome.DEAD

        try:
            self.handler(job)
        except Exception:
            deliveries = self._deliveries(stream, entry_id)
            logger.exception("job failed id=%s case=%s deliveries=%d", entry_id, job.case_id, deliveries)
            if deliveries >= self.cfg.max_deliveries:
                self._dead_letter(stream, entry_id, fields, "max_deliveries")
                return Outcome.DEAD
            return Outcome.RETRY

        self.r.xack(stream, self.cfg.group, entry_id)
        return Outcome.DONE

    def _process_response(self, response: Any) -> int:
        """XREADGROUP 응답을 우선순위 순서로 처리한다."""
        by_stream = {name: entries for name, entries in (response or [])}
        handled = 0
        for stream in self.cfg.streams:
            for entry_id, fields in by_stream.get(stream, []):
                self.process(entry_id, fields, stream)
                handled += 1
        return handled

    def run_once(self) -> None:
        # 1) 오래 멈춘 메시지 회수
        for stream in self.cfg.streams:
            _, claimed, _ = self.r.xautoclaim(
                stream, self.cfg.group, self.cfg.consumer, self.cfg.min_idle_ms, start_id="0-0", count=5
            )
            for entry_id, fields in claimed:
                self.process(entry_id, fields, stream)

        # 2) 우선순위가 높은 스트림부터 기다리지 않고 한 건 읽는다. 신고·수동 건이 있으면 피드 건보다 먼저 처리된다.
        for stream in self.cfg.streams:
            response = self.r.xreadgroup(self.cfg.group, self.cfg.consumer, {stream: ">"}, count=1)
            if self._process_response(response):
                return

        # 3) 둘 다 비었으면 두 스트림을 함께 기다린다.
        response = self.r.xreadgroup(
            self.cfg.group,
            self.cfg.consumer,
            {stream: ">" for stream in self.cfg.streams},
            count=1,
            block=self.cfg.block_ms,
        )
        self._process_response(response)
