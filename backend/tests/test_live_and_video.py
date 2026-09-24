"""실시간 조사 화면(라이브 뷰)과 조사 녹화(video) 증거 시험."""

import uuid
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services import live
from tests.test_investigation_api import AUTH, _claim, _job, _new_case, _put

JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64
WEBM = b"\x1a\x45\xdf\xa3" + b"\x00" * 64


class FakeFrames:
    def __init__(self) -> None:
        self.data: dict[str, tuple[bytes, int | None]] = {}

    def set(self, name: str, value: bytes, ex: int | None = None) -> None:
        self.data[name] = (value, ex)

    def get(self, name: str) -> bytes | None:
        item = self.data.get(name)
        return item[0] if item else None


@pytest.fixture
def frames(app: FastAPI) -> FakeFrames:
    store = FakeFrames()
    app.dependency_overrides[live.get_frame_store] = lambda: store
    return store


def _post_frame(
    client: TestClient,
    case_id: str,
    data: bytes = JPEG,
    ctype: str = "image/jpeg",
    job: str | None = None,
    headers=None,
):  # noqa: ANN001, ANN202, E501
    return client.post(
        f"/internal/v1/cases/{case_id}/live",
        content=data,
        headers={
            **(AUTH if headers is None else headers),
            "Content-Type": ctype,
            "X-Job-Id": job or _job(client, case_id),
        },
    )


def test_live_frame_round_trip_with_short_ttl(client: TestClient, frames: FakeFrames) -> None:
    case_id = _new_case(client, "https://live.example.com/")
    assert client.get(f"/api/v1/cases/{case_id}/live").status_code == 204
    assert _claim(client, case_id).status_code == 200
    assert _post_frame(client, case_id).status_code == 204
    r = client.get(f"/api/v1/cases/{case_id}/live")
    assert r.status_code == 200 and r.content == JPEG and r.headers["content-type"] == "image/jpeg"
    assert r.headers["cache-control"] == "no-store"
    ((_, ttl),) = frames.data.values()
    assert ttl == 20  # 증거가 아니라 잠깐만 둔다


@pytest.mark.parametrize(
    ("data", "ctype", "code"),
    [
        (b"<svg onload=alert(1)>", "image/jpeg", 422),
        (JPEG, "image/svg+xml", 415),
        (JPEG + b"\x00" * 300_000, "image/jpeg", 413),
    ],
    ids=["not_jpeg", "wrong_type", "too_large"],
)
def test_live_frame_validation(client: TestClient, frames: FakeFrames, data: bytes, ctype: str, code: int) -> None:
    case_id = _new_case(client, "https://live-bad.example.com/")
    _claim(client, case_id)
    assert _post_frame(client, case_id, data, ctype).status_code == code
    assert frames.data == {}


def test_live_frame_only_from_current_investigating_job(client: TestClient, frames: FakeFrames) -> None:
    case_id = _new_case(client, "https://live-state.example.com/")
    assert _post_frame(client, case_id).status_code == 409  # 아직 queued
    _claim(client, case_id)
    assert _post_frame(client, case_id, job=str(uuid.uuid4())).status_code == 409  # 다른 작업
    assert _post_frame(client, case_id, headers={}).status_code == 401  # 서비스 토큰 없음
    assert frames.data == {}


def test_live_frame_respects_case_access(app: FastAPI, as_user: Callable[..., TestClient], frames: FakeFrames) -> None:
    kim = as_user("kim", "investigator")
    lee = as_user("lee", "investigator")
    case_id = _new_case(kim, "https://live-idor.example.com/")
    _claim(kim, case_id)
    _post_frame(kim, case_id)
    assert kim.get(f"/api/v1/cases/{case_id}/live").status_code == 200
    assert lee.get(f"/api/v1/cases/{case_id}/live").status_code == 404


def test_video_evidence_is_validated_and_served(client: TestClient) -> None:
    case_id = _new_case(client, "https://video.example.com/")
    _claim(client, case_id)
    assert _put(client, case_id, "video", b"not a webm", "video/webm").status_code == 422
    assert _put(client, case_id, "video", WEBM, "video/mp4").status_code == 415
    res = _put(client, case_id, "video", WEBM, "video/webm")
    assert res.status_code == 201
    ev = res.json()
    content = client.get(f"/api/v1/cases/{case_id}/evidence/{ev['id']}/content")
    assert content.status_code == 200 and content.content == WEBM
    assert content.headers["content-type"] == "video/webm"
    assert content.headers["x-evidence-sha256"] == ev["sha256"]
    assert content.headers["x-content-type-options"] == "nosniff"
