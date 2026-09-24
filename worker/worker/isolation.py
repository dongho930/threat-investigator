"""수집 격리 실행: 한 번의 수집을 별도 프로세스 그룹에서 돌리고, 전체 시간 제한을 넘으면 그룹째 강제 종료한다.

D2 평가(대용량 문서, 약 40MB 글자·2만 개 입력칸)에서 렌더러가 멈춰 page.title()·page.evaluate()가 끝나지 않았고
(두 호출은 시간 제한이 없다), Worker 전체가 30분 넘게 멈췄다. 악성 페이지 하나로 모든 조사가 멈추는 서비스 거부다.
Playwright 호출마다 시간 제한을 붙이는 것만으로는 빠짐이 생길 수 있어, 프로세스 경계에서 막는다.

- 자식 프로세스는 새 프로세스 그룹을 만들고(Chromium이 그 안에서 뜬다), 시간 초과 시 SIGKILL로 그룹 전체를 끝낸다.
- 결과(Artifacts)는 파이프로 받는다. 자식이 예외로 끝나면 부모에서 오류를 올려 collector_error로 보고된다.
- 수집기는 자식이 직접 만든다(make_collect: 인자 없는 최상위 함수). 부모의 수집기 객체는 SSL 설정 등을 품고 있어
  자식 프로세스로 넘길 수 없다(첫 배포에서 모든 수집이 collector_error가 된 원인).
"""

import logging
import multiprocessing
import os
import signal
from collections.abc import Callable
from typing import Any

from worker.collector import Artifacts, NetworkState

logger = logging.getLogger(__name__)

Collect = Callable[[str], Artifacts]


def _child(make_collect: Callable[[], Collect], url: str, conn: Any) -> None:
    if hasattr(os, "setpgrp"):
        os.setpgrp()  # 이 프로세스와 여기서 뜨는 브라우저를 한 그룹으로 묶는다
    try:
        conn.send(("ok", make_collect()(url)))
    except Exception:  # 오류 원문은 부모로 보내지 않는다(로그에만)
        logging.getLogger(__name__).exception("isolated collect failed")
        conn.send(("error", None))
    finally:
        conn.close()


def _kill_group(proc: Any) -> None:
    if hasattr(os, "killpg"):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    proc.kill()


def timeout_artifacts(url: str) -> Artifacts:
    from worker.collector import Collector

    return Artifacts(
        "failed",
        "collection_timeout",
        {"schema": "redirect_chain/1", "hops": [], "final_url": url[:2048]},
        Collector._network_summary(NetworkState()),
    )


class IsolatedCollector:
    def __init__(self, make_collect: Callable[[], Collect], deadline_s: float, start_method: str = "spawn") -> None:
        self.make_collect = make_collect
        self.deadline_s = deadline_s
        self.ctx = multiprocessing.get_context(start_method)

    def __call__(self, url: str) -> Artifacts:
        parent, child = self.ctx.Pipe(duplex=False)
        proc = self.ctx.Process(target=_child, args=(self.make_collect, url, child), daemon=True)
        proc.start()
        child.close()
        try:
            if not parent.poll(self.deadline_s):
                logger.warning("collection exceeded %.0fs, killing process group pid=%s", self.deadline_s, proc.pid)
                _kill_group(proc)
                return timeout_artifacts(url)
            try:
                kind, result = parent.recv()
            except EOFError:
                kind, result = "error", None
        finally:
            parent.close()
            proc.join(timeout=5)
            if proc.is_alive():
                _kill_group(proc)
                proc.join(timeout=5)
        if kind != "ok" or not isinstance(result, Artifacts):
            raise RuntimeError("isolated collector failed")
        return result
