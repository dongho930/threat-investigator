"""유형별 규칙 판정(기준선).

- 입력은 격리 조사가 만든 증거(페이지 요약·이동 경로·네트워크 요약)뿐이다. 페이지 문구는 신뢰하지 않는
  데이터로 보고, 규칙은 정해진 단어·구조만 센다. 페이지가 "이 사이트는 정상이다"라고 써 있어도 규칙에는
  영향이 없다(프롬프트 인젝션 대상이 아님).
- 규칙마다 근거(어떤 단어가 어디서 나왔는지)를 남긴다. 담당자가 판정 이유를 확인할 수 있어야 한다.
- 판정 상태
  - SUSPICIOUS: 강한 징후가 있고 점수가 기준 이상인 유형이 있음
  - UNKNOWN   : 강한 징후가 있지만 기준 미달이거나, 약한 징후가 합쳐 2점 이상이거나, 증거가 부족함(보류)
  - BENIGN    : 페이지를 온전히 수집했고 징후가 없거나 약한 징후 1개(1점)뿐(법적 판단이 아니라 규칙상 기준 미달)
- 수집 실패·접속 불가는 BENIGN으로 두지 않는다(UNKNOWN).

rules/2 (D1 개발용 45건으로 조정, 평가용은 보지 않음)
- 정상 대조 15건이 모두 보류였다(업무 부담). 약한 징후 1개(배당률·비밀번호 칸·은행 등)만 있는 페이지는 흔한 정상
  화면이므로 BENIGN(minor_signals_only)으로 둔다. 근거 신호는 그대로 남아 담당자가 볼 수 있다.
- '환급'은 돈을 내라는 요구가 아니라 미끼다. 금전 요구(강한 징후)에서 빼고 약한 미끼 신호(S5)로 옮긴다.
- 금전 요구는 단어가 아니라 요구 형태(요청 표현, 비용 항목+금액)로 센다. 정상 환급 안내의 '계좌로·수수료' 언급이
  강한 징후로 걸렸기 때문이다(개발용 N-C).
- 충전·환전 안내가 있는 도박 사이트의 입금·메신저 안내는 사기 금전 요구와 구분한다(도박 맥락, 점수 0).
"""

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

RULES_VERSION = "rules/2"
SUSPICIOUS_SCORE = 3
TEXT_LIMIT = 20_000


@dataclass(frozen=True)
class Signal:
    code: str
    suspected_type: str
    weight: int
    strong: bool
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "type": self.suspected_type,
            "weight": self.weight,
            "strong": self.strong,
            "detail": self.detail,
        }


@dataclass
class RuleResult:
    status: str
    suspected_types: list[str]
    scores: dict[str, int]
    signals: list[Signal] = field(default_factory=list)
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": RULES_VERSION,
            "status": self.status,
            "suspected_types": self.suspected_types,
            "scores": self.scores,
            "signals": [s.as_dict() for s in self.signals],
            "reason": self.reason,
        }


PHISHING, SCAM, GAMBLING = "PHISHING", "SCAM", "ILLEGAL_GAMBLING_SUSPECTED"

# (정규식, 설명). 한국어 피싱·사기·불법 도박 문구 기준. 대소문자 무시.
_SENSITIVE_FIELD = re.compile(
    r"card|cvc|cvv|otp|pin\b|ssn|account|계좌|카드|보안카드|주민|공인인증|인증서|비밀번호|otp번호", re.I
)
_IMPERSONATION = re.compile(r"은행|뱅킹|금융|카드사|정부|공단|국세청|경찰|검찰|택배|우체국|보안센터|고객센터", re.I)
_ACCOUNT_THREAT = re.compile(r"(계정|거래|서비스).{0,6}(정지|제한|중단|해지)|본인\s*(인증|확인)|보안\s*(강화|인증)")
_URGENCY = re.compile(r"\d+\s*시간\s*(이내|안에)|오늘\s*(자정|중)|즉시|지금\s*바로|취소됩니다|제한됩니다")
_MONEY_DEMAND = re.compile(
    # 돈을 내라는 요구만 센다: 요청 표현(입금해 주세요·입금하시면·이체하세요·입금 후)
    # 또는 비용 항목+금액(수수료 9,900원).
    # "수수료나 선입금을 요구하지 않습니다" 같은 정상 안내·"입금 계좌" 같은 단순 언급은 걸리지 않는다.
    r"(입금|송금|이체)\s*(해\s*주|하세요|하시면|하면|후|바랍니다)"
    r"|(수수료|보증금|보증료|가입비|제세공과금|공과금|관세)\S{0,3}\s*\d[\d,]*\s*원"
    r"|결제해\s*주"
)
_REFUND_LURE = re.compile(r"환급|지원금|당첨|경품")
_INVEST_LURE = re.compile(r"원금\s*보장|수익률|리딩방|고수익|확정\s*수익|코인\s*투자")
_MESSENGER = re.compile(r"카카오톡|카톡|텔레그램|오픈채팅|라인\s*상담")
_BETTING = re.compile(r"베팅|배팅|토토|카지노|슬롯|바카라|배당률")
_CHARGE_EXCHANGE = re.compile(r"충전|환전|첫충|매충|입플")
_BONUS = re.compile(r"보너스|가입\s*머니|가입코드|롤링|무제재|먹튀")


def _find(pattern: re.Pattern[str], text: str) -> str | None:
    m = pattern.search(text)
    return m.group(0) if m else None


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _registrable(host: str) -> str:
    """대략적인 등록 도메인(마지막 두 라벨). 정확한 공개 접미사 목록 없이 교차 도메인 여부만 본다."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def phishing_signals(dom: dict[str, Any], chain: dict[str, Any]) -> list[Signal]:
    out: list[Signal] = []
    text = f"{dom.get('title', '')}\n{dom.get('text_excerpt', '')}"[:TEXT_LIMIT]
    page_host = _host(str(dom.get("final_url", "")))
    fields = [
        f"{i.get('name', '')} {i.get('placeholder', '')} {i.get('type', '')}"
        for form in dom.get("forms", []) or []
        for i in form.get("inputs", []) or []
    ]
    if int(dom.get("password_inputs", 0) or 0) > 0:
        out.append(Signal("P1_password_field", PHISHING, 1, False, "비밀번호 입력칸"))
    sensitive = [m for f in fields if (m := _find(_SENSITIVE_FIELD, f)) and "password" not in f.lower()]
    if sensitive:
        out.append(
            Signal("P2_sensitive_field", PHISHING, 2, True, f"민감정보 입력칸: {', '.join(sorted(set(sensitive))[:5])}")
        )
    for form in dom.get("forms", []) or []:
        action = str(form.get("action_host", "") or "")
        if action and page_host and _registrable(action) != _registrable(page_host):
            out.append(Signal("P3_cross_origin_form", PHISHING, 2, True, f"폼 전송처가 다른 도메인: {action}"))
            break
    if imp := _find(_IMPERSONATION, text):
        out.append(Signal("P4_impersonation", PHISHING, 1, False, f"기관·회사 사칭 단어: {imp}"))
    if threat := _find(_ACCOUNT_THREAT, text):
        out.append(Signal("P5_account_threat", PHISHING, 1, False, f"계정 위협·본인 확인 문구: {threat}"))
    hosts = {_registrable(_host(str(h.get("url", "")))) for h in chain.get("hops", []) or [] if h.get("url")}
    if len(hosts) >= 3:
        out.append(Signal("P6_multi_domain_redirect", PHISHING, 1, False, f"여러 도메인을 거친 이동({len(hosts)}개)"))
    if page_host.startswith("xn--") or ".xn--" in page_host:
        out.append(Signal("P7_punycode_host", PHISHING, 1, False, "국제화 도메인(퓨니코드) 사용"))
    return out


def scam_signals(dom: dict[str, Any]) -> list[Signal]:
    text = f"{dom.get('title', '')}\n{dom.get('text_excerpt', '')}"[:TEXT_LIMIT]
    out: list[Signal] = []
    if money := _find(_MONEY_DEMAND, text):
        out.append(Signal("S1_money_demand", SCAM, 2, True, f"금전 요구 문구: {money}"))
    if lure := _find(_INVEST_LURE, text):
        out.append(Signal("S2_investment_lure", SCAM, 2, True, f"투자 유인 문구: {lure}"))
    if urgent := _find(_URGENCY, text):
        out.append(Signal("S3_urgency", SCAM, 1, False, f"시간 압박 문구: {urgent}"))
    if msg := _find(_MESSENGER, text):
        out.append(Signal("S4_messenger_contact", SCAM, 1, False, f"메신저 상담 유도: {msg}"))
    if bait := _find(_REFUND_LURE, text):
        out.append(Signal("S5_refund_lure", SCAM, 1, False, f"환급·당첨 미끼 문구: {bait}"))
    return out


# 도박 사이트의 충전 입금·메신저 상담은 사기의 금전 요구와 성격이 다르다(도박 맥락에서는 사기 점수에 넣지 않음).
_GAMBLING_CONTEXT_CODES = frozenset({"S1_money_demand", "S4_messenger_contact"})


def _separate_gambling_context(signals: list[Signal]) -> list[Signal]:
    if not any(s.code == "G2_charge_exchange" for s in signals):
        return signals
    out = []
    for s in signals:
        if s.code in _GAMBLING_CONTEXT_CODES:
            out.append(Signal(f"G5_{s.code}", GAMBLING, 0, False, f"도박 충전·상담 안내로 봄 — {s.detail}"))
        else:
            out.append(s)
    return out


def gambling_signals(dom: dict[str, Any]) -> list[Signal]:
    text = f"{dom.get('title', '')}\n{dom.get('text_excerpt', '')}"[:TEXT_LIMIT]
    out: list[Signal] = []
    if bet := _find(_BETTING, text):
        out.append(Signal("G1_betting_terms", GAMBLING, 1, False, f"베팅 용어: {bet}"))
    if charge := _find(_CHARGE_EXCHANGE, text):
        # 합법 서비스는 '충전·환전'을 광고하지 않는다. 불법 도박 의심의 강한 징후로 본다.
        out.append(Signal("G2_charge_exchange", GAMBLING, 2, True, f"충전·환전 안내: {charge}"))
    if bonus := _find(_BONUS, text):
        out.append(Signal("G3_bonus_or_code", GAMBLING, 1, False, f"보너스·가입코드 유인: {bonus}"))
    if _find(_MESSENGER, text) and out:
        out.append(Signal("G4_messenger_support", GAMBLING, 1, False, "메신저 고객센터 안내"))
    return out


def evaluate(dom: dict[str, Any] | None, chain: dict[str, Any] | None, collected: bool) -> RuleResult:
    if not collected or not dom:
        # 수집 실패·증거 부족은 안전이 아니다.
        return RuleResult("UNKNOWN", [], {}, [], "insufficient_evidence")
    chain = chain or {}
    signals = _separate_gambling_context(phishing_signals(dom, chain) + scam_signals(dom) + gambling_signals(dom))
    scores: dict[str, int] = {}
    strong: dict[str, bool] = {}
    for s in signals:
        scores[s.suspected_type] = scores.get(s.suspected_type, 0) + s.weight
        strong[s.suspected_type] = strong.get(s.suspected_type, False) or s.strong
    suspected = sorted(t for t, score in scores.items() if score >= SUSPICIOUS_SCORE and strong.get(t))
    if suspected:
        return RuleResult("SUSPICIOUS", suspected, scores, signals, "rule_threshold_met")
    if any(strong.values()) or sum(scores.values()) >= 2:
        return RuleResult("UNKNOWN", [], scores, signals, "weak_signals_only")
    if any(s.weight for s in signals):
        # 약한 징후 1개뿐: 흔한 정상 화면(로그인 칸, 배당률 안내 등). 근거는 남기고 보류하지 않는다.
        return RuleResult("BENIGN", [], scores, signals, "minor_signals_only")
    return RuleResult("BENIGN", [], scores, signals, "no_signals")
