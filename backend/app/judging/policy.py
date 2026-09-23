"""규칙 판정과 AI 모델 판단을 합치는 정책.

원칙(기획서 2.4·3.2, SC-AI-01):
- 모델 출력만으로는 SUSPICIOUS(제보 자격)를 만들 수 없다. 모델만 의심하면 보류(UNKNOWN)다.
- 규칙과 모델이 다르면 보류한다(사람이 먼저 본다).
- 모델 장애·시간 초과·출력 검증 실패는 보류다(제보 보류). 안전(BENIGN)으로 두지 않는다.
- 페이지에서 AI를 조작하려는 문구가 보이면 모델 답을 쓰지 않고, 규칙이 SUSPICIOUS가 아니면 보류한다.
- 모델 자체 확신도가 기준보다 낮으면 모델은 기권으로 보고 규칙 결과를 따른다.
"""

from dataclasses import dataclass
from typing import Any

from app.judging.models import SUSPECTED_TYPE, ModelResult, SiteType

SUSPICIOUS, BENIGN, UNKNOWN = "SUSPICIOUS", "BENIGN", "UNKNOWN"


@dataclass(frozen=True)
class Combined:
    status: str
    suspected_types: list[str]
    reason: str
    model_used: bool


def combine(
    rule: dict[str, Any],
    model: ModelResult | None,
    *,
    model_error: str | None,
    injection: list[str],
    min_confidence: float,
) -> Combined:
    rule_status = rule["status"]
    rule_types = list(rule.get("suspected_types") or [])
    rule_reason = rule.get("reason", "")

    if injection:
        status = SUSPICIOUS if rule_status == SUSPICIOUS else UNKNOWN
        return Combined(status, rule_types, "prompt_injection_suspected", model_used=False)
    if model_error is not None or model is None:
        return Combined(UNKNOWN, rule_types, "model_unavailable", model_used=False)
    if model.confidence is not None and model.confidence < min_confidence:
        return Combined(rule_status, rule_types, f"{rule_reason}+model_abstained", model_used=False)

    site = model.answer.site_type
    model_type = SUSPECTED_TYPE.get(site)
    if rule_status == SUSPICIOUS:
        if model_type is not None and model_type in rule_types:
            return Combined(SUSPICIOUS, rule_types, "rule_model_agree", model_used=True)
        return Combined(UNKNOWN, rule_types, "rule_model_conflict", model_used=True)
    if site is SiteType.NORMAL:
        # 규칙이 BENIGN이면 그대로, UNKNOWN(약한 징후·증거 부족)이면 보류를 유지한다.
        reason = "rule_model_agree" if rule_status == BENIGN else rule_reason
        return Combined(rule_status, rule_types, reason, model_used=True)
    # 규칙은 의심하지 않는데 모델만 의심: 제보 자격 없음, 사람이 먼저 보도록 보류
    return Combined(UNKNOWN, rule_types, "model_only_signal", model_used=True)
