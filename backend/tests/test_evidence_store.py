import uuid

import pytest

from app.services.evidence_store import InvalidStorageKey, LocalEvidenceStore


def test_put_and_get_roundtrip(tmp_path) -> None:
    store = LocalEvidenceStore(tmp_path)
    case_id = uuid.uuid4()
    obj = store.put(case_id, b"{}", "json")
    assert obj.key.startswith(f"{case_id}/")
    assert store.get(obj.key) == b"{}"
    assert obj.size_bytes == 2
    assert not list(tmp_path.rglob("*.tmp"))


@pytest.mark.parametrize(
    "key",
    [
        "../../etc/passwd",
        "/etc/passwd",
        f"{uuid.uuid4()}/../../secret.json",
        f"{uuid.uuid4()}/{uuid.uuid4().hex}.html",
        f"{uuid.uuid4()}\\{uuid.uuid4().hex}.png",
        "",
    ],
)
def test_rejects_unexpected_keys(tmp_path, key: str) -> None:
    with pytest.raises(InvalidStorageKey):
        LocalEvidenceStore(tmp_path).get(key)


def test_rejects_unknown_extension(tmp_path) -> None:
    with pytest.raises(ValueError):
        LocalEvidenceStore(tmp_path).put(uuid.uuid4(), b"x", "html")
