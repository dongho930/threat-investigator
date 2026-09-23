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
    group: str = os.getenv("JOB_GROUP", "investigators")
    consumer: str = os.getenv("WORKER_NAME", socket.gethostname())
    dead_letter_stream: str = os.getenv("DEAD_LETTER_STREAM", "jobs:dead")
    max_deliveries: int = int(os.getenv("MAX_DELIVERIES", "5"))
    min_idle_ms: int = int(os.getenv("RECLAIM_IDLE_MS", "60000"))
    block_ms: int = 5000


Handler = Callable[[JobMessage], None]


class Consumer:
    def __init__(self, client: Any, handler: Handler, config: ConsumerConfig | None = None) -> None:
        self.r = client
        self.handler = handler
        self.cfg = config or ConsumerConfig()

    def ensure_group(self) -> None:
        try:
            self.r.xgroup_create(self.cfg.stream, self.cfg.group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def _dead_letter(self, entry_id: str, fields: dict[str, str], reason: str) -> None:
        self.r.xadd(self.cfg.dead_letter_stream, {"source_id": entry_id, "reason": reason, **fields}, maxlen=10_000)
        self.r.xack(self.cfg.stream, self.cfg.group, entry_id)

    def _deliveries(self, entry_id: str) -> int:
        pending = self.r.xpending_range(self.cfg.stream, self.cfg.group, min=entry_id, max=entry_id, count=1)
        return int(pending[0]["times_delivered"]) if pending else 1

    def process(self, entry_id: str, fields: dict[str, str]) -> Outcome:
        try:
            job = parse_job(fields)
        except InvalidMessage as exc:
            logger.warning("invalid message id=%s reason=%s", entry_id, exc)
            self._dead_letter(entry_id, fields, "invalid_message")
            return Outcome.DEAD

        try:
            self.handler(job)
        except Exception:
            deliveries = self._deliveries(entry_id)
            logger.exception("job failed id=%s case=%s deliveries=%d", entry_id, job.case_id, deliveries)
            if deliveries >= self.cfg.max_deliveries:
                self._dead_letter(entry_id, fields, "max_deliveries")
                return Outcome.DEAD
            return Outcome.RETRY

        self.r.xack(self.cfg.stream, self.cfg.group, entry_id)
        return Outcome.DONE

    def run_once(self) -> None:
        _, claimed, _ = self.r.xautoclaim(
            self.cfg.stream, self.cfg.group, self.cfg.consumer, self.cfg.min_idle_ms, start_id="0-0", count=5
        )
        for entry_id, fields in claimed:
            self.process(entry_id, fields)

        response = self.r.xreadgroup(
            self.cfg.group, self.cfg.consumer, {self.cfg.stream: ">"}, count=1, block=self.cfg.block_ms
        )
        for _stream, entries in response or []:
            for entry_id, fields in entries:
                self.process(entry_id, fields)
