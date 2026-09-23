import logging
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_MAX_LOG_VALUE = 500


def safe_log_value(value: object) -> str:
    """로그 삽입(CWE-117) 방지: 개행·제어문자를 제거하고 길이를 제한한다."""
    text = _CONTROL_CHARS.sub(" ", str(value))
    if len(text) > _MAX_LOG_VALUE:
        text = text[:_MAX_LOG_VALUE] + "…"
    return text


def redact_url(url: str) -> str:
    """URL 쿼리 값에 토큰·개인정보가 있을 수 있으므로 로그에는 값을 가린다."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<invalid-url>"
    query = urlencode([(k, "***") for k, _ in parse_qsl(parts.query, keep_blank_values=True)])
    return safe_log_value(urlunsplit((parts.scheme, parts.netloc, parts.path, query, "")))


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
