"""신고 CSV 일괄 등록 시험."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import AuditLog, Case, CaseSource, OutboxEvent, Report
from app.services.reports import parse_reported_at

HEADER = "접수번호,신고일시,URL,메모\r\n"


def _post(client: TestClient, text: str, *, encoding: str = "utf-8", bom: bool = False, ctype: str = "text/csv"):
    data = text.encode(encoding)
    if bom:
        data = b"\xef\xbb\xbf" + data
    return client.post("/api/v1/reports/import", content=data, headers={"Content-Type": ctype})


def test_import_creates_and_merges_by_url(client: TestClient) -> None:
    csv_text = (
        HEADER
        + "R-001,2026-09-20 09:00,https://phish.example.com/login,문자 신고\r\n"
        + "R-002,2026-09-20 10:30,https://PHISH.example.com/login#frag,같은 사이트 중복 신고\r\n"
        + "R-003,2026-09-21,https://scam.example.org/,\r\n"
    )
    res = _post(client, csv_text, bom=True)
    assert res.status_code == 200
    body = res.json()
    assert (body["total"], body["created"], body["merged"], body["duplicate"], body["rejected"]) == (3, 2, 1, 0, 0)

    with client.app.state.session_factory() as db:
        cases = db.scalars(select(Case)).all()
        assert len(cases) == 2 and {c.source for c in cases} == {CaseSource.REPORT}
        assert len(db.scalars(select(OutboxEvent)).all()) == 2  # 병합된 신고는 새 조사를 만들지 않는다
        phish = next(c for c in cases if c.host == "phish.example.com")
        audit = db.scalars(select(AuditLog).where(AuditLog.action == "report.import")).one()
    assert audit.after["merged"] == 1

    reports = client.get(f"/api/v1/cases/{phish.id}/reports").json()["items"]
    assert [r["report_no"] for r in reports] == ["R-001", "R-002"]
    # 원본 URL(신고된 그대로)은 신고마다 보존된다
    assert reports[1]["url_reported"] == "https://PHISH.example.com/login#frag"
    assert client.get(f"/api/v1/cases/{phish.id}").json()["source"] == "report"


def test_reupload_same_file_is_idempotent(client: TestClient) -> None:
    csv_text = HEADER + "R-100,2026-09-20 09:00,https://again.example.com/,\r\n"
    assert _post(client, csv_text).json()["created"] == 1
    second = _post(client, csv_text).json()
    assert (second["created"], second["merged"], second["duplicate"]) == (0, 0, 1)
    with client.app.state.session_factory() as db:
        assert len(db.scalars(select(Report)).all()) == 1


def test_cp949_file_from_korean_excel(client: TestClient) -> None:
    res = _post(client, HEADER + "K-1,2026/09/20 09:00,https://cp949.example.com/,한글 메모\r\n", encoding="cp949")
    assert res.status_code == 200 and res.json()["created"] == 1
    with client.app.state.session_factory() as db:
        assert db.scalars(select(Report)).one().note == "한글 메모"


def test_row_errors_report_line_and_code_without_echo(client: TestClient) -> None:
    csv_text = (
        HEADER
        + "bad no!,2026-09-20,https://a.example.com/,\r\n"  # 2
        + "R-1,not-a-date,https://b.example.com/,\r\n"  # 3
        + "R-2,2999-01-01,https://c.example.com/,\r\n"  # 4
        + "R-3,2026-09-20,http://169.254.169.254/latest/meta-data/,\r\n"  # 5
        + "R-4,2026-09-20,https://ok.example.com/,\r\n"  # 6
        + "R-4,2026-09-20,https://ok2.example.com/,\r\n"  # 7
        + f"R-5,2026-09-20,https://d.example.com/,{'x' * 501}\r\n"  # 8
        + "R-6,2026-09-20,javascript:alert(1),\r\n"  # 9
    )
    res = _post(client, csv_text)
    body = res.json()
    assert body["created"] == 1 and body["rejected"] == 7
    assert body["errors"] == [
        {"row": 2, "code": "invalid_report_no"},
        {"row": 3, "code": "invalid_reported_at"},
        {"row": 4, "code": "future_reported_at"},
        {"row": 5, "code": "ip_not_allowed"},
        {"row": 7, "code": "duplicate_in_file"},
        {"row": 8, "code": "note_too_long"},
        {"row": 9, "code": "scheme_not_allowed"},
    ]
    assert "169.254" not in res.text and "alert(1)" not in res.text


@pytest.mark.parametrize(
    ("text", "status", "code"),
    [
        ("", 422, "empty_file"),
        ("번호,날짜\r\n1,2\r\n", 422, "missing_columns"),
    ],
)
def test_whole_file_rejections(client: TestClient, text: str, status: int, code: str) -> None:
    res = _post(client, text)
    assert res.status_code == status and res.json()["code"] == code


def test_binary_garbage_rejected() -> None:
    from app.services.reports import ReportImportError, decode_csv

    with pytest.raises(ReportImportError) as exc:
        decode_csv(b"\xff\xfe\xfd\x80\x81")
    assert exc.value.code == "invalid_encoding"


def test_too_many_rows(client: TestClient) -> None:
    rows = "".join(f"R-{i},2026-09-20,https://r{i}.example.com/,\r\n" for i in range(1001))
    res = _post(client, HEADER + rows)
    assert res.status_code == 413 and res.json()["code"] == "too_many_rows"
    with client.app.state.session_factory() as db:
        assert db.scalars(select(Case)).all() == []  # 한도를 넘으면 한 행도 등록하지 않는다


def test_oversized_body_and_wrong_type(client: TestClient) -> None:
    big = HEADER + "x" * (1024 * 1024 + 10)
    assert _post(client, big).status_code == 413
    assert _post(client, HEADER, ctype="application/json").status_code == 415


def test_formula_like_values_are_stored_as_text(client: TestClient) -> None:
    # 나중에 CSV로 내보낼 때는 수식 삽입을 막아야 한다. 저장은 원문 그대로, 화면에는 텍스트로만 표시한다.
    _post(client, HEADER + 'R-9,2026-09-20,https://f.example.com/,"=HYPERLINK(""http://evil"")"\r\n')
    with client.app.state.session_factory() as db:
        assert db.scalars(select(Report)).one().note == '=HYPERLINK("http://evil")'


def test_reported_at_timezones() -> None:
    now = datetime(2026, 9, 24, tzinfo=UTC)
    assert parse_reported_at("2026-09-20 09:00", now) == datetime(2026, 9, 20, 0, 0, tzinfo=UTC)  # KST로 해석
    assert parse_reported_at("2026-09-20T09:00:00+00:00", now) == datetime(2026, 9, 20, 9, 0, tzinfo=UTC)
    with pytest.raises(ValueError, match="future_reported_at"):
        parse_reported_at("2026-09-26", now)
