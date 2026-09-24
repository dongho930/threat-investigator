"""증거 파일 저장소 (로컬 디스크).

- 저장 키는 서버가 만든 `<case_id>/<uuid>.<ext>` 형식만 쓴다. Worker나 사용자가 보낸 이름은 쓰지 않는다(SC-IN-04).
- 읽을 때도 키 형식을 다시 검사하고, 실제 경로가 저장소 루트 밖으로 나가지 않는지 확인한다.
- 같은 키에 덮어쓰지 않는다(`xb` 모드). 임시 파일에 쓴 뒤 rename해서 반쯤 쓰인 파일이 보이지 않게 한다.
"""

import hashlib
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path

_EXTENSIONS = frozenset({"png", "json", "webm"})
_KEY_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[0-9a-f]{32}\.(png|json|webm)$"
)


class InvalidStorageKey(ValueError):
    pass


@dataclass(frozen=True)
class StoredObject:
    key: str
    sha256: str
    size_bytes: int


class LocalEvidenceStore:
    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root).resolve()

    def _path(self, key: str) -> Path:
        if not _KEY_PATTERN.fullmatch(key):
            raise InvalidStorageKey("storage key has unexpected format")
        path = (self.root / key).resolve()
        if not path.is_relative_to(self.root):
            raise InvalidStorageKey("storage key escapes root")
        return path

    def put(self, case_id: uuid.UUID, data: bytes, ext: str) -> StoredObject:
        if ext not in _EXTENSIONS:
            raise ValueError("unsupported extension")
        key = f"{case_id}/{uuid.uuid4().hex}.{ext}"
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        with open(tmp, "xb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        return StoredObject(key=key, sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data))

    def get(self, key: str) -> bytes:
        with open(self._path(key), "rb") as fh:
            return fh.read()

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)
