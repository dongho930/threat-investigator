"""평가 지표 계산(기획서 2.6절 (5): 모든 비율은 건수와 95% Wilson 신뢰구간을 함께)."""

import math

Z95 = 1.959963984540054


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def ratio(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    pct = f"{100 * k / n:.1f}%" if n else "-"
    return f"{k}/{n} ({pct}, 95% CI {100 * lo:.1f}~{100 * hi:.1f}%)"


TYPE_OF = {"phishing": "PHISHING", "scam": "SCAM", "gambling": "ILLEGAL_GAMBLING_SUSPECTED"}


def d1_metrics(rows: list[dict]) -> dict:
    """rows: {label, variant, status, suspected_types, final_path_ok}"""
    out: dict = {}
    for label, t in TYPE_OF.items():
        positives = [r for r in rows if r["label"] == label]
        tp = sum(r["status"] == "SUSPICIOUS" and t in r["suspected_types"] for r in positives)
        predicted = [r for r in rows if r["status"] == "SUSPICIOUS" and t in r["suspected_types"]]
        out[label] = {
            "recall": ratio(tp, len(positives)),
            "precision": ratio(sum(r["label"] == label for r in predicted), len(predicted)),
            "held": ratio(sum(r["status"] == "UNKNOWN" for r in positives), len(positives)),
        }
    normals = [r for r in rows if r["label"] == "normal"]
    out["normal"] = {
        "false_suspicious": ratio(sum(r["status"] == "SUSPICIOUS" for r in normals), len(normals)),
        "held": ratio(sum(r["status"] == "UNKNOWN" for r in normals), len(normals)),
        "benign": ratio(sum(r["status"] == "BENIGN" for r in normals), len(normals)),
    }
    dynamic = [r for r in rows if r["label"] != "normal" and r["variant"] in ("delayed", "jsnav")]
    out["dynamic_capture"] = ratio(
        sum(r["status"] == "SUSPICIOUS" and TYPE_OF[r["label"]] in r["suspected_types"] for r in dynamic), len(dynamic)
    )
    moved = [r for r in rows if r["variant"] in ("redirect", "jsnav")]
    out["final_destination"] = ratio(sum(bool(r["final_path_ok"]) for r in moved), len(moved))
    out["held_overall"] = ratio(sum(r["status"] == "UNKNOWN" for r in rows), len(rows))
    out["failed"] = sum(r["status"] == "FAILED" for r in rows)
    return out
