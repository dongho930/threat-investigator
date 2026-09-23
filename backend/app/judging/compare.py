"""모델 비교 도구. 같은 증거·같은 질문으로 모델을 돌려 정확도·시간·인젝션 결과를 표로 낸다.

    docker compose --profile qwen run --rm -v ./backend/tests/fixtures/dom:/fixtures:ro ai-judge \\
        python -m app.judging.compare /fixtures

폴더에는 <이름>.json(dom_summary·redirect_chain)과 labels.json({이름: 정답 site_type})이 있어야 한다.
모델 단독 결과와, 규칙·인젝션 탐지·정책을 거친 최종 판정을 함께 보여 준다(모델 단독 점수만으로 채택하지 않는다).
"""

import argparse
import json
import sys
from pathlib import Path

from app.core.config import get_settings
from app.judging import injection, policy, rules
from app.judging.ai_worker import make_adapter
from app.judging.models import ModelError, build_facts

EXPECTED_STATUS = {"normal": {"BENIGN", "UNKNOWN"}}  # 정상 페이지는 SUSPICIOUS만 아니면 된다(보류는 따로 센다)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.judging.compare")
    parser.add_argument("folder", type=Path)
    parser.add_argument(
        "--raw", action="store_true", help="인젝션 탐지와 관계없이 모든 페이지를 모델에 보낸다(모델 단독 측정)"
    )
    args = parser.parse_args(argv)

    settings = get_settings()
    adapter = make_adapter(settings)
    if adapter is None:
        print("AI_MODEL이 none입니다.", file=sys.stderr)
        return 2
    labels = json.loads((args.folder / "labels.json").read_text(encoding="utf-8"))
    rows = []
    for name, truth in labels.items():
        if name.startswith("_"):
            continue
        data = json.loads((args.folder / f"{name}.json").read_text(encoding="utf-8"))
        dom, chain = data.get("dom_summary"), data.get("redirect_chain")
        rule = rules.evaluate(dom, chain, True).as_dict()
        codes = injection.detect(dom)
        model, error = None, None
        if codes and not args.raw:
            pass
        else:
            try:
                model = adapter.classify(build_facts(dom or {}, chain))
            except ModelError as exc:
                error = exc.code
        combined = policy.combine(
            rule, model, model_error=error, injection=codes, min_confidence=settings.ai_min_confidence
        )
        final_ok = (
            combined.status in EXPECTED_STATUS[truth]
            if truth == "normal"
            else combined.status == "SUSPICIOUS" and rules_type(truth) in combined.suspected_types
        )
        rows.append(
            {
                "page": name,
                "truth": truth,
                "model": model.answer.site_type.value if model else (error or "skipped"),
                "model_ok": bool(model and model.answer.site_type.value == truth),
                "confidence": model.confidence if model else None,
                "latency_ms": model.latency_ms if model else None,
                "injection": codes,
                "rule": rule["status"],
                "final": combined.status,
                "reason": combined.reason,
                "final_ok": final_ok,
            }
        )

    name = getattr(adapter, "name", settings.ai_model)
    print(f"model={name} revision={getattr(adapter, 'revision', '-')} raw={args.raw}")
    print(f"{'page':18} {'truth':9} {'model':10} {'conf':>5} {'ms':>6}  {'rule':10} {'final':10} reason")
    for r in rows:
        conf = f"{r['confidence']:.2f}" if r["confidence"] is not None else "-"
        ms = str(r["latency_ms"]) if r["latency_ms"] is not None else "-"
        mark = "O" if r["model_ok"] else "X"
        print(
            f"{r['page']:18} {r['truth']:9} {r['model']:9}{mark} {conf:>5} {ms:>6}  {r['rule']:10} {r['final']:10} "
            f"{r['reason']}{' inj=' + ','.join(r['injection']) if r['injection'] else ''}"
        )
    sent = [r for r in rows if r["latency_ms"] is not None]
    print(
        f"model_correct={sum(r['model_ok'] for r in rows)}/{len(rows)} "
        f"final_correct={sum(r['final_ok'] for r in rows)}/{len(rows)} "
        f"false_suspicious={sum(r['truth'] == 'normal' and r['final'] == 'SUSPICIOUS' for r in rows)} "
        f"mean_latency_ms={int(sum(r['latency_ms'] for r in sent) / len(sent)) if sent else '-'}"
    )
    print(json.dumps(rows, ensure_ascii=False))
    return 0


def rules_type(site: str) -> str:
    return {"phishing": rules.PHISHING, "scam": rules.SCAM, "gambling": rules.GAMBLING}[site]


if __name__ == "__main__":
    raise SystemExit(main())
