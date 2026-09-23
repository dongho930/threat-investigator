"""위협정보 피드 자동 탐색으로 들어온 URL 등록.

피드 수집기(feed-collector)가 체크섬을 확인한 목록을 내부 API로 보낸다. 여기서는 URL마다 등록 화면과 같은
정책 검사를 하고, 하루에 새로 만드는 사건 수를 제한한다. 피드에 올라왔다는 사실은 판정 근거가 아니며,
등록된 사건도 격리 조사를 거쳐야 심의 자료가 된다.
"""

import logging
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import AuditLog, Case, CaseSource
from app.security.url_policy import UrlPolicyError
from app.services.cases import create_case

logger = logging.getLogger(__name__)


@dataclass
class FeedImportResult:
    received: int = 0
    created: int = 0
    duplicate: int = 0
    rejected: int = 0
    capped: int = 0


def created_today(db: Session, now: datetime) -> int:
    """오늘(UTC) 피드로 새로 만든 사건 수."""
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    query = select(func.count()).select_from(Case).where(Case.source == CaseSource.FEED, Case.created_at >= start)
    return db.scalar(query) or 0


def import_feed(
    db: Session, settings: Settings, *, source: str, urls: list[str], now: datetime | None = None
) -> FeedImportResult:
    now = now or datetime.now(UTC)
    result = FeedImportResult(received=len(urls))
    budget = max(0, settings.feed_max_new_cases_per_day - created_today(db, now))
    for url in urls:
        if budget <= 0:
            result.capped += 1
            continue
        try:
            _case, duplicate = create_case(
                db, settings, url=url, note=None, actor="feed-collector", source=CaseSource.FEED, source_ref=source
            )
        except UrlPolicyError:
            result.rejected += 1
            continue
        if duplicate:
            result.duplicate += 1
        else:
            result.created += 1
            budget -= 1
    db.add(
        AuditLog(
            actor="feed-collector", action="feed.import", target_type="feed", target_id=source, after=asdict(result)
        )
    )
    db.commit()
    logger.info(
        "feed import source=%s received=%d created=%d duplicate=%d rejected=%d capped=%d",
        source,
        result.received,
        result.created,
        result.duplicate,
        result.rejected,
        result.capped,
    )
    return result
