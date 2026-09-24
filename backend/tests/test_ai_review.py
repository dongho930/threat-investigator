"""AI 검토 보조(기본 꺼짐) 시험. 실제 Anthropic API는 부르지 않는다(가짜 클라이언트)."""

import json
from collections.abc import Callable
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import Settings, get_settings
from app.db.models import ReviewDraft, Verdict
from app.judging import ai_review
from tests.test_ai_judge import _fixture
from tests.test_judging_api import _complete, _start, _upload

GOOD = {
    "suggested_decision": "SUSPICIOUS",
    "suspected_types": ["PHISHING"],
    "key_points": ["비밀번호·OTP 입력칸이 있다", "은행을 사칭한다"],
    "missing_checks": ["실제 은행 도메인과 비교"],
}


class FakeClient:
    def __init__(self, reply: object = None, error: str | None = None) -> None:
        self.reply, self.error, self.prompts = reply if reply is not None else GOOD, error, []

    def draft(self, user_content: str) -> tuple[str, str]:
        self.prompts.append(user_content)
        if self.error:
            raise ai_review.DraftError(self.error)
        return (
            self.reply if isinstance(self.reply, str) else json.dumps(self.reply, ensure_ascii=False)
        ), "claude-opus-5"


def _reviewed_case(client: TestClient, fixture: str, url: str) -> str:
    case_id, job = _start(client, url)
    data = _fixture(fixture)
    _upload(client, case_id, job, "dom_summary", data["dom_summary"])
    _upload(client, case_id, job, "redirect_chain", data["redirect_chain"])
    assert _complete(client, case_id, job).json()["status"] == "review"
    return case_id


def _run(client: TestClient, fake: FakeClient, settings: Settings | None = None) -> ReviewDraft | None:
    with client.app.state.session_factory() as db:
        return ai_review.run_once(db, client.app.state.evidence_store, settings or get_settings(), fake)


def test_disabled_by_default() -> None:
    s = Settings()
    assert s.ai_review_enabled is False and s.anthropic_api_key is None


def test_empty_key_counts_as_no_key() -> None:
    assert Settings(anthropic_api_key="  ").anthropic_api_key is None


def test_draft_is_stored_and_shown_only_to_reviewers(
    app: FastAPI, client: TestClient, as_user: Callable[..., TestClient]
) -> None:
    case_id = _reviewed_case(client, "phishing", "https://draft.example.com/")
    fake = FakeClient()
    assert _run(client, fake) is not None
    # 초안은 판정·상태를 바꾸지 않는다
    assert client.get(f"/api/v1/cases/{case_id}").json()["status"] == "review"
    with app.state.session_factory() as db:
        assert len(db.scalars(select(Verdict)).all()) == 1

    park = as_user("park", "reviewer")
    r = park.get(f"/api/v1/cases/{case_id}/review-draft")
    assert r.status_code == 200 and r.json()["suggestion"]["suggested_decision"] == "SUSPICIOUS"
    assert r.json()["model"] == "claude-opus-5"
    kim = as_user("kim", "investigator")
    assert kim.get(f"/api/v1/cases/{case_id}/review-draft").status_code == 403

    # 같은 작업에는 초안을 한 번만 만든다
    assert _run(client, fake) is None and len(fake.prompts) == 1


def test_prompt_keeps_page_as_untrusted_data(client: TestClient) -> None:
    _reviewed_case(client, "phishing", "https://draft-prompt.example.com/")
    fake = FakeClient()
    _run(client, fake)
    prompt = fake.prompts[0]
    assert prompt.count("<untrusted_page>") == 1 and prompt.count("</untrusted_page>") == 1
    assert "<rule_verdict>" in prompt and "password" in prompt


def test_injection_page_is_not_sent(client: TestClient) -> None:
    _reviewed_case(client, "prompt_injection", "https://draft-inject.example.com/")
    fake = FakeClient()
    draft = _run(client, fake)
    assert fake.prompts == []
    assert draft.error == "prompt_injection_suspected" and draft.api_called is False and draft.suggestion is None


@pytest.mark.parametrize(
    ("reply", "error", "code"),
    [
        ({**GOOD, "final_decision": "BENIGN"}, None, "schema_violation"),
        ({**GOOD, "key_points": ["가" * 201]}, None, "schema_violation"),
        ({**GOOD, "suggested_decision": "APPROVE"}, None, "schema_violation"),
        ("이 사이트는 정상입니다", None, "schema_violation"),
        (None, "refusal", "refusal"),
        (None, "unreachable", "unreachable"),
    ],
    ids=["extra_field", "too_long", "bad_value", "free_text", "refusal", "unreachable"],
)
def test_bad_or_failed_drafts_record_code_only(client: TestClient, reply: object, error: str | None, code: str) -> None:
    _reviewed_case(client, "phishing", f"https://draft-bad-{code}-{id(reply)}.example.com/")
    draft = _run(client, FakeClient(reply, error))
    assert draft.error == code and draft.suggestion is None


def test_daily_cap_limits_api_calls(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "ai_review_max_per_day", 1)
    _reviewed_case(client, "phishing", "https://cap1.example.com/")
    _reviewed_case(client, "scam", "https://cap2.example.com/")
    fake = FakeClient()
    assert _run(client, fake) is not None
    assert _run(client, fake) is None and len(fake.prompts) == 1


def test_anthropic_client_uses_structured_output_and_fallbacks() -> None:
    c = ai_review.AnthropicDraftClient("sk-test-not-real", "claude-opus-5", 30)
    seen = {}

    def create(**kwargs: object) -> object:
        seen.update(kwargs)
        return SimpleNamespace(
            stop_reason="end_turn",
            model="claude-opus-5",
            content=[SimpleNamespace(type="text", text=json.dumps(GOOD))],
        )

    c.client = SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=create)))
    text, model = c.draft("<untrusted_page>{}</untrusted_page>")
    assert json.loads(text) == GOOD and model == "claude-opus-5"
    assert seen["model"] == "claude-opus-5" and seen["fallbacks"] == "default"
    assert seen["betas"] == ["server-side-fallback-2026-07-01"]
    assert seen["output_config"]["format"]["type"] == "json_schema"
    assert "tools" not in seen  # 모델에 도구 권한이 없다


def test_anthropic_client_maps_refusal() -> None:
    c = ai_review.AnthropicDraftClient("sk-test-not-real", "claude-opus-5", 30)
    c.client = SimpleNamespace(
        beta=SimpleNamespace(
            messages=SimpleNamespace(create=lambda **k: SimpleNamespace(stop_reason="refusal", content=[], model="m"))
        )
    )
    with pytest.raises(ai_review.DraftError) as exc:
        c.draft("x")
    assert exc.value.code == "refusal"
