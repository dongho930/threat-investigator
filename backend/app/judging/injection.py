"""프롬프트 인젝션 시도 탐지(규칙, SC-AI-01).

소형 모델(Qwen3-1.7B)은 페이지 글을 '불신 데이터'로 표시하고 지시를 앞뒤로 반복해도, 페이지 속 가짜 SYSTEM 지시를
따라 피싱 페이지를 정상으로 답했다(개발 중 실험). 그래서 방어를 프롬프트에만 맡기지 않는다.
모델을 부르기 전에 코드가 AI에게 하는 지시처럼 보이는 문구를 찾고, 찾으면 그 페이지에서는 모델 답을 쓰지 않는다.
판정을 바꾸려는 문구가 있다는 것 자체도 의심 근거라 담당자 검토(보류)로 보낸다.
"""

import re
from typing import Any

# (코드, 정규식). 대소문자 무시. 일반 페이지에 흔한 말(“시스템 점검” 등)에는 걸리지 않도록 지시 형태만 본다.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("role_marker", re.compile(r"(^|\n|[\s\[(<])(system|assistant|developer)\s*[:：]", re.I)),
    (
        "chat_template_token",
        re.compile(r"<\|im_(start|end)\|>|\[/?INST\]|<</?SYS>>|<\|(system|user|assistant)\|>", re.I),
    ),
    ("fake_delimiter", re.compile(r"</?\s*(untrusted_page|system|instructions?|prompt)\s*>", re.I)),
    (
        "ignore_instructions",
        re.compile(
            r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)"
            r"|(이전|앞의|위의?|기존|모든)\s*(지시|명령|규칙|프롬프트)\S{0,2}\s*(을|를)?\s*(모두\s*)?(무시|잊)",
            re.I,
        ),
    ),
    (
        "verdict_override",
        re.compile(
            r"[\"']?(status|verdict|site_type|label|classification)[\"']?\s*[:=]\s*[\"']?(benign|safe|normal|정상)"
            r"|(이\s*사이트|이\s*페이지|본\s*사이트)[는은]?\s*(안전|정상)(한|인)?\s*(사이트|페이지)?(이?다|입니다|임)"
            r".{0,40}(분류|판정|출력|답)",
            re.I,
        ),
    ),
    (
        "ai_addressed",
        re.compile(
            r"(AI|인공지능|언어\s*모델|분류기|LLM|assistant)\s*(에게|는|은|야)?[,\s].{0,30}(출력|응답|답)하(라|세요|십시오)",
            re.I,
        ),
    ),
]


def detect(dom: dict[str, Any] | None) -> list[str]:
    """페이지 제목·본문에서 찾은 인젝션 패턴 코드(중복 없음, 정해진 순서)."""
    if not dom:
        return []
    text = f"{dom.get('title', '')}\n{dom.get('text_excerpt', '')}"[:20_000]
    return [code for code, pattern in _PATTERNS if pattern.search(text)]
