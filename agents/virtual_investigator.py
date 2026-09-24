"""가상 조사자(자동화 계정). 시연·부하 시험용으로 신고 목록 CSV를 올리고 결과를 모아 보고한다.

    AGENT_USER=agent-inv1 AGENT_PASSWORD=... python agents/virtual_investigator.py --rounds 1 --size 10

- 계정은 `agent-`로 시작하는 조사자여야 한다(CLI가 강제). 판정 확정은 할 수 없다(서버가 거부, 사람만 확정).
- 사람이 하는 일과 구분되게 신고 메모에 "가상 신고(자동)"를 붙이고, 콘솔에는 등록자가 agent-로 보인다.
- 신고 URL은 **D1 개발용 페이지만** 쓴다(평가용은 쓰지 않는다). 실제 인터넷 주소는 쓰지 않는다.
- 결과는 "자동화 시험"으로만 보고한다. 기획서 2.6절 사용자 평가(사람 참가자)를 대신하지 않는다.
- 표준 라이브러리만 쓴다(평가 실행기 eval/run.py의 콘솔 클라이언트를 재사용).
"""

import argparse
import csv
import io
import json
import os
import random
import statistics
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))
from run import SITE, Console  # noqa: E402

AGENT_PREFIX = "agent-"
FINISHED = {"review", "failed", "held", "rejected", "confirmed", "reported"}


def dev_pages() -> list[dict]:
    manifest = json.loads((ROOT / "eval" / "d1" / "manifest.json").read_text(encoding="utf-8"))
    return [p for p in manifest["pages"] if p["split"] == "dev"]


def build_csv(pages: list[dict], batch: str, rng: random.Random) -> tuple[bytes, list[str]]:
    now = datetime.now(UTC).astimezone()
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["접수번호", "신고일시", "URL", "메모"])
    urls = []
    for i, page in enumerate(pages, 1):
        url = f"{SITE}{page['url']}?agent={batch}-{i}"
        urls.append(url)
        reported = now - timedelta(minutes=rng.randrange(5, 600))
        writer.writerow([f"AGT-{batch}-{i:03d}", reported.strftime("%Y-%m-%d %H:%M"), url, "가상 신고(자동)"])
    return out.getvalue().encode("utf-8"), urls


def import_csv(con: Console, data: bytes) -> dict:
    status, body, _ = con._call_raw("POST", "/api/v1/reports/import", data, "text/csv")
    if status != 200:
        raise SystemExit(f"CSV 등록 실패: {status} {body}")
    return body


def wait_for(con: Console, marker: str, expected: int, timeout_s: float) -> list[dict]:
    deadline = time.monotonic() + timeout_s
    mine: list[dict] = []
    while time.monotonic() < deadline:
        items = con.get("/api/v1/cases?limit=100")["items"]
        mine = [c for c in items if marker in c["url"]]
        if len(mine) >= expected and all(c["status"] in FINISHED for c in mine):
            break
        time.sleep(3)
    return mine


def run_round(con: Console, size: int, rng: random.Random, timeout_s: float) -> dict:
    batch = datetime.now(UTC).strftime("%m%d%H%M%S")
    pages = rng.sample(dev_pages(), size)
    data, _ = build_csv(pages, batch, rng)
    started = time.monotonic()
    result = import_csv(con, data)
    print(
        f"[{batch}] 신고 {result['total']}건 등록: 새 사건 {result['created']} · "
        f"병합 {result['merged']} · 거부 {result['rejected']}",
        flush=True,
    )
    cases = wait_for(con, f"agent={batch}-", result["created"], timeout_s)
    elapsed = time.monotonic() - started
    verdicts = {}
    for c in cases:
        items = con.get(f"/api/v1/cases/{c['id']}/verdicts")["items"]
        system = next((v for v in items if v["decided_by"] == "system"), None)
        key = system["status"] if system else c["status"].upper()
        verdicts[key] = verdicts.get(key, 0) + 1
    done = [c for c in cases if c["status"] in FINISHED]
    summary = {
        "batch": batch,
        "reports": result["total"],
        "cases": len(cases),
        "finished": len(done),
        "verdicts": verdicts,
        "elapsed_s": round(elapsed, 1),
        "per_case_s": round(elapsed / max(len(done), 1), 1),
    }
    print(
        f"[{batch}] 처리 {len(done)}/{len(cases)}건, {summary['elapsed_s']}초 "
        f"(건당 {summary['per_case_s']}초) · 판정 {verdicts}",
        flush=True,
    )
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="가상 조사자(자동화 시험용)")
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--size", type=int, default=10, help="한 번에 올릴 신고 수(개발용 페이지 45개 중)")
    ap.add_argument("--interval", type=float, default=60, help="회차 사이 대기(초)")
    ap.add_argument("--timeout", type=float, default=900)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    user = os.environ["AGENT_USER"]
    if not user.startswith(AGENT_PREFIX):
        raise SystemExit("가상 조사자는 agent- 계정으로만 실행한다(사람 계정과 구분).")
    con = Console(user, os.environ["AGENT_PASSWORD"])
    rng = random.Random(args.seed)
    summaries = []
    for i in range(args.rounds):
        if i:
            time.sleep(args.interval)
        summaries.append(run_round(con, min(args.size, 45), rng, args.timeout))
    per_case = [s["per_case_s"] for s in summaries if s["finished"]]
    if per_case:
        print(
            f"전체 {len(summaries)}회: 건당 평균 {statistics.mean(per_case):.1f}초 (자동화 시험 결과, 사용자 평가 아님)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
