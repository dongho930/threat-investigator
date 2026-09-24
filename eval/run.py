"""평가 실행기. 실행 중인 콘솔(nginx → backend)에 조사자 계정으로 사건을 등록하고 결과를 모은다.

    EVAL_USER=eval-runner EVAL_PASSWORD=... python eval/run.py d1 --split dev
    EVAL_USER=eval-runner EVAL_PASSWORD=... python eval/run.py d2

- D1 평가용(--split eval)은 규칙·모델·프롬프트를 고정한 뒤 한 번만 연다(기획서 2.6절). 작업 트리가 깨끗해야 하고
  --frozen-evaluation을 붙여야 하며, 실행 전에 고정 기록(git 커밋·규칙 버전·AI 모델)을 먼저 남긴다.
- 같은 URL은 한 사건으로 묶이므로 실행마다 ?run=<실행 ID>를 붙인다(규칙은 URL 쿼리를 보지 않는다).
- 표준 라이브러리만 쓴다. 세션 쿠키는 Secure라 http://127.0.0.1에서 쿠키 저장소가 보내지 않으므로 직접 붙인다.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from metrics import d1_metrics  # noqa: E402

BASE = os.environ.get("EVAL_BASE_URL", "http://127.0.0.1:8080")
SITE = "http://testsites:8080"
DONE = {"review", "failed", "held", "rejected", "confirmed", "reported"}


class Console:
    def __init__(self, user: str, password: str) -> None:
        self.cookie = ""
        self.csrf = ""
        status, body, headers = self._call("POST", "/api/v1/auth/login", {"username": user, "password": password})
        if status != 200:
            raise SystemExit(f"로그인 실패: {status} {body}")
        self.cookie = headers.get("Set-Cookie", "").split(";", 1)[0]
        self.csrf = body["csrf_token"]

    def _call(self, method: str, path: str, body: dict | None = None) -> tuple[int, object, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(BASE + path, data=data, method=method)  # noqa: S310
        req.add_header("Content-Type", "application/json")
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        if self.csrf and method != "GET":
            req.add_header("X-CSRF-Token", self.csrf)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310  # nosec B310
                raw, status, headers = resp.read(), resp.status, resp.headers
        except urllib.error.HTTPError as exc:
            raw, status, headers = exc.read(), exc.code, exc.headers
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = raw
        return status, parsed, headers

    def get(self, path: str) -> object:
        status, body, _ = self._call("GET", path)
        if status != 200:
            raise RuntimeError(f"GET {path} → {status}")
        return body

    def create(self, url: str) -> str:
        status, body, _ = self._call("POST", "/api/v1/cases", {"url": url})
        if status not in (200, 201) or not body.get("case"):
            raise RuntimeError(f"등록 실패 {url}: {status} {body}")
        return body["case"]["id"]

    def wait(self, ids: dict[str, str], timeout_s: float) -> dict[str, dict]:
        cases: dict[str, dict] = {}
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            pending = [k for k, cid in ids.items() if cases.get(k, {}).get("status") not in DONE]
            if not pending:
                break
            for k in pending:
                cases[k] = self.get(f"/api/v1/cases/{ids[k]}")
            time.sleep(2)
        return cases

    def evidence_json(self, case_id: str, kind: str) -> dict | None:
        items = self.get(f"/api/v1/cases/{case_id}/evidence")["items"]
        found = sorted((e for e in items if e["kind"] == kind), key=lambda e: -e["version"])
        if not found:
            return None
        return self.get(f"/api/v1/cases/{case_id}/evidence/{found[0]['id']}/content")

    def latest_system_verdict(self, case_id: str) -> dict | None:
        items = self.get(f"/api/v1/cases/{case_id}/verdicts")["items"]
        return next((v for v in items if v["decided_by"] == "system"), None)


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=HERE.parent, capture_output=True, text=True, check=True).stdout.strip()


def full_url(path: str, run_id: str) -> str:
    url = path if path.startswith("http") else SITE + path
    return url + ("&" if "?" in url else "?") + f"run={run_id}"


def run_d1(con: Console, split: str, run_id: str, out: Path, timeout_s: float) -> None:
    manifest = json.loads((HERE / "d1" / "manifest.json").read_text(encoding="utf-8"))
    pages = [p for p in manifest["pages"] if p["split"] == split]
    ids = {p["id"]: con.create(full_url(p["url"], run_id)) for p in pages}
    print(f"{len(ids)}건 등록, 결과 대기…", flush=True)
    cases = con.wait(ids, timeout_s)
    rows = []
    for p in pages:
        cid = ids[p["id"]]
        case = cases.get(p["id"], {})
        verdict = con.latest_system_verdict(cid) if case.get("status") in DONE else None
        dom = con.evidence_json(cid, "dom_summary") if case.get("status") == "review" else None
        final = (dom or {}).get("final_url", "")
        status = "FAILED" if case.get("status") == "failed" else (verdict or {}).get("status", "PENDING")
        rows.append(
            {
                **{k: p[k] for k in ("id", "label", "family", "variant")},
                "case_id": cid,
                "case_status": case.get("status"),
                "status": status,
                "suspected_types": (verdict or {}).get("suspected_types", []),
                "reason": (verdict or {}).get("policy_reason"),
                "model": ((verdict or {}).get("model_result") or {}).get("site_type"),
                "final_path_ok": final.split("?", 1)[0].endswith(p["final_path"]),
            }
        )
    metrics = d1_metrics(rows)
    out.write_text(json.dumps({"rows": rows, "metrics": metrics}, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(metrics, ensure_ascii=False, indent=1))
    for r in rows:
        print(
            f"  {r['family']:4} {r['variant']:8} {r['label']:9} → {r['status']:10} "
            f"{','.join(r['suspected_types']):28} {r['reason']}"
        )


def check_scenario(con: Console, sc: dict, case: dict, case_id: str, run_id: str) -> tuple[bool, list[str]]:
    exp, notes, ok = sc["expect"], [], True

    def fail(msg: str) -> None:
        nonlocal ok
        ok = False
        notes.append(msg)

    status = case.get("status")
    if status not in exp["status_in"]:
        fail(f"status={status}")
    if "reason_in" in exp and case.get("status_reason") not in exp["reason_in"]:
        fail(f"reason={case.get('status_reason')}")
    net = con.evidence_json(case_id, "network_summary") if status in ("review", "judging") else None
    dom = con.evidence_json(case_id, "dom_summary") if status in ("review", "judging") else None
    if exp.get("subresource_violation"):
        viol = [r for r in (net or {}).get("subresource_redirects", []) if r.get("violation")]
        if not viol:
            fail("하위 자원 위반 기록 없음")
        else:
            notes.append(f"하위 자원 차단 {len(viol)}건")
    if "popups_blocked_min" in exp:
        n = (net or {}).get("popups_blocked", 0)
        if n < exp["popups_blocked_min"]:
            fail(f"popups_blocked={n}")
        else:
            notes.append(f"팝업 {n}개 닫음")
    if "evidence_kinds_subset" in exp:
        kinds = {e["kind"] for e in con.get(f"/api/v1/cases/{case_id}/evidence")["items"]}
        if not kinds <= set(exp["evidence_kinds_subset"]):
            fail(f"예상 밖 증거 {kinds}")
        else:
            notes.append(f"증거 {sorted(kinds)}")
    if "text_not_contains" in exp:
        text = (dom or {}).get("text_excerpt", "")
        if exp["text_not_contains"] in text:
            fail(f"본문에 {exp['text_not_contains']}")
        else:
            notes.append(next((w for w in text.split() if w.startswith("SW:")), "SW 결과 없음"))
    if "verdict_not" in exp or exp.get("injection_detected"):
        v = con.latest_system_verdict(case_id) or {}
        if v.get("status") in exp.get("verdict_not", []):
            fail(f"verdict={v.get('status')}")
        inj = (v.get("rule_result") or {}).get("injection") or ((v.get("model_result") or {}).get("injection")) or []
        if exp.get("injection_detected") and not inj:
            fail("인젝션 미탐지")
        notes.append(f"판정 {v.get('status')} · 탐지 {inj}")
    if "dom_summary_max_bytes" in exp and dom is not None:
        size = len(json.dumps(dom, ensure_ascii=False).encode())
        if size > exp["dom_summary_max_bytes"]:
            fail(f"페이지 요약 {size}B")
        else:
            notes.append(
                f"페이지 요약 {size // 1024}KB, 입력칸 {sum(len(f['inputs']) for f in dom.get('forms', []))}개 기록"
            )
    if exp.get("console_no_dialog"):
        notes.append(console_dialog_check(f"{sc['url']}?run={run_id}"))
        if not notes[-1].startswith("콘솔 표시 중 스크립트 실행 0건"):
            ok = False
    return ok, notes


def console_dialog_check(url_part: str) -> str:
    """콘솔에서 사건 상세를 열어 스크립트 실행(대화상자)이 없는지 본다. Playwright가 없으면 건너뛴다."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return "콘솔 확인 건너뜀(Playwright 없음)"
    dialogs: list[str] = []
    try:
        _open_case_in_console(sync_playwright, url_part, dialogs)
    except Exception as exc:  # 확인 자체가 안 되면 통과로 치지 않는다
        return f"콘솔 확인 실패: {type(exc).__name__}"
    return f"대화상자 {len(dialogs)}건" if dialogs else "콘솔 표시 중 스크립트 실행 0건"


def _open_case_in_console(sync_playwright: Any, url_part: str, dialogs: list[str]) -> None:
    with sync_playwright() as p:
        b = p.chromium.launch()
        page = b.new_page()
        page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
        page.goto(BASE)
        page.fill("#username", os.environ["EVAL_USER"])
        page.fill("#password", os.environ["EVAL_PASSWORD"])
        page.click("button[type=submit]")
        page.wait_for_selector("text=로그아웃")
        page.locator("tr.clickable", has_text=url_part).first.click()
        page.wait_for_selector("text=페이지 요약", timeout=60_000)
        page.wait_for_timeout(1500)
        b.close()


def run_d2(con: Console, run_id: str, out: Path, timeout_s: float) -> None:
    scenarios = json.loads((HERE / "d2" / "scenarios.json").read_text(encoding="utf-8"))["scenarios"]
    ids = {s["id"]: con.create(full_url(s["url"], run_id)) for s in scenarios}
    print(f"{len(ids)}건 등록, 결과 대기…", flush=True)
    cases = con.wait(ids, timeout_s)
    results = []
    for s in scenarios:
        ok, notes = check_scenario(con, s, cases.get(s["id"], {}), ids[s["id"]], run_id)
        results.append(
            {
                "id": s["id"],
                "name": s["name"],
                "blocked": ok,
                "status": cases.get(s["id"], {}).get("status"),
                "reason": cases.get(s["id"], {}).get("status_reason"),
                "notes": notes,
            }
        )
        print(
            f"{s['id']} {'차단' if ok else '실패'}  {s['name']} · {cases.get(s['id'], {}).get('status')}"
            f"/{cases.get(s['id'], {}).get('status_reason')} · {'; '.join(notes)}"
        )
    # 대용량 문서 뒤에도 Worker가 살아 있는지: 정상 페이지 하나를 더 조사한다
    probe = con.create(full_url("/benign-shop.html", run_id + "-alive"))
    alive = con.wait({"probe": probe}, 120).get("probe", {}).get("status") == "review"
    print(f"Worker 생존 확인: {'정상' if alive else '실패'}")
    blocked = sum(r["blocked"] for r in results) if alive else 0
    print(f"D2 차단 {blocked}/{len(results)}")
    out.write_text(
        json.dumps({"results": results, "worker_alive": alive}, ensure_ascii=False, indent=1), encoding="utf-8"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", choices=["d1", "d2"])
    ap.add_argument("--split", choices=["dev", "eval"], default="dev")
    ap.add_argument("--frozen-evaluation", action="store_true")
    ap.add_argument("--timeout", type=float, default=1800)
    ap.add_argument("--tag", default="")
    args = ap.parse_args()

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S") + (f"-{args.tag}" if args.tag else "")
    results = HERE / "results"
    results.mkdir(exist_ok=True)
    if args.dataset == "d1" and args.split == "eval":
        if not args.frozen_evaluation:
            raise SystemExit("평가용은 --frozen-evaluation을 붙여 고정 평가로만 실행한다.")
        if git("status", "--porcelain"):
            raise SystemExit("작업 트리가 깨끗하지 않다. 고정할 커밋을 먼저 만든다.")
        freeze = {
            "run_id": run_id,
            "commit": git("rev-parse", "HEAD"),
            "ai_model": os.environ.get("AI_MODEL", "?"),
            "note": "규칙·모델·프롬프트는 이 커밋으로 고정",
        }
        (results / f"{run_id}-freeze.json").write_text(
            json.dumps(freeze, ensure_ascii=False, indent=1), encoding="utf-8"
        )
    con = Console(os.environ["EVAL_USER"], os.environ["EVAL_PASSWORD"])
    out = results / f"{run_id}-{args.dataset}{'-' + args.split if args.dataset == 'd1' else ''}.json"
    if args.dataset == "d1":
        run_d1(con, args.split, run_id, out, args.timeout)
    else:
        run_d2(con, run_id, out, args.timeout)
    print(f"저장: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
