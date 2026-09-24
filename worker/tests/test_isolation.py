"""수집 격리 실행 시험. 수집이 멈춰도 Worker는 시간 제한 뒤 돌아오고, 자식이 띄운 프로세스까지 정리된다."""

import os
import pickle
import subprocess
import sys
import time
from pathlib import Path

import pytest

from worker.collector import Artifacts
from worker.isolation import IsolatedCollector

OK = Artifacts("collected", None, {"schema": "redirect_chain/1", "hops": [], "final_url": "u"}, {"schema": "n"})


def quick(url: str, live: object = None) -> Artifacts:
    return Artifacts(
        "collected", None, {"schema": "redirect_chain/1", "hops": [], "final_url": url}, {"x": 1}, None, b"png"
    )


def hang(url: str, live: object = None) -> Artifacts:
    time.sleep(3600)
    raise AssertionError("unreachable")


def boom(url: str, live: object = None) -> Artifacts:
    raise ValueError("secret detail /etc/passwd")


def hang_with_grandchild(url: str, live: object = None) -> Artifacts:
    # 브라우저처럼 자식 프로세스를 띄운 채 멈춘다. pid를 파일에 적어 시험이 생존 여부를 본다.
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(3600)"])  # noqa: S603
    Path(url).write_text(str(child.pid))
    time.sleep(3600)
    raise AssertionError("unreachable")


def make_quick():  # noqa: ANN201
    return quick


def make_hang():  # noqa: ANN201
    return hang


def make_boom():  # noqa: ANN201
    return boom


def make_hang_with_grandchild():  # noqa: ANN201
    return hang_with_grandchild


def test_real_collector_factory_can_cross_process_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    """부모의 수집기 객체(SSL 설정 포함)는 자식으로 넘길 수 없다. 넘기는 것은 인자 없는 공장 함수여야 한다."""
    from worker.collector import Collector
    from worker.main import build_collector

    monkeypatch.setenv("EGRESS_PROXY_URL", "http://egress-proxy:3128")
    assert isinstance(build_collector(), Collector)
    # 공장 함수는 자식으로 넘어간다. (수집기 객체 자체는 Linux에서 SSLContext 때문에 넘어가지 않았다: 첫 배포 장애)
    assert pickle.loads(pickle.dumps(build_collector)) is build_collector  # noqa: S301 (시험 안에서 만든 값만 복원)


def test_returns_artifacts_from_child() -> None:
    result = IsolatedCollector(make_quick, deadline_s=60)("http://testsites:8080/")
    assert result.outcome == "collected" and result.screenshot == b"png"
    assert result.redirect_chain["final_url"] == "http://testsites:8080/"


def test_hung_collection_is_cut_off_at_deadline() -> None:
    started = time.monotonic()
    result = IsolatedCollector(make_hang, deadline_s=3)("http://testsites:8080/d2/huge.html")
    assert time.monotonic() - started < 15
    assert (result.outcome, result.reason) == ("failed", "collection_timeout")
    assert result.dom_summary is None and result.screenshot is None
    assert result.network_summary["schema"] == "network_summary/2"


def test_child_error_is_reported_without_detail() -> None:
    with pytest.raises(RuntimeError) as exc:
        IsolatedCollector(make_boom, deadline_s=30)("http://testsites:8080/")
    assert "passwd" not in str(exc.value)


@pytest.mark.skipif(not hasattr(os, "killpg"), reason="프로세스 그룹은 POSIX에서만 시험")
def test_timeout_kills_whole_process_group(tmp_path: Path) -> None:
    pid_file = tmp_path / "grandchild.pid"
    IsolatedCollector(make_hang_with_grandchild, deadline_s=5)(str(pid_file))
    pid = int(pid_file.read_text())
    time.sleep(0.5)
    try:
        os.kill(pid, 0)
        # 좀비(이미 죽었지만 거둬지지 않음)는 살아 있는 것으로 보지 않는다
        state = Path(f"/proc/{pid}/stat").read_text().split()[2] if Path(f"/proc/{pid}/stat").exists() else "Z"
        assert state == "Z", "손자 프로세스가 살아 있음"
    except ProcessLookupError:
        pass
