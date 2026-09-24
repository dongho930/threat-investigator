"""D1 시험 페이지 생성기. 같은 입력이면 항상 같은 파일을 만든다(시드 고정).

    python eval/generate.py        # testsites/html/d1/*.html, eval/d1/manifest.json 생성

변형(variant)
- static   : 내용이 HTML에 그대로 있다.
- delayed  : HTML에는 base64로 감춘 내용만 있고, 1.2~2초 뒤 스크립트가 그린다(정적 검사로는 보이지 않음).
- redirect : 같은 서버의 3단계 HTTP 리다이렉트(/r3 → /r2 → /r1 → 페이지)를 거쳐 도착한다.
- jsnav    : 첫 페이지가 스크립트로 다른 페이지로 이동한다(정적 검사는 첫 페이지만 본다).

파일 이름은 의미 없는 ID라 URL에서 정답(유형·개발/평가)이 드러나지 않는다.
"""

import base64
import hashlib
import json
import random
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from d1_families import FAMILIES  # noqa: E402

OUT_HTML = ROOT / "testsites" / "html" / "d1"
OUT_MANIFEST = Path(__file__).resolve().parent / "d1" / "manifest.json"
SALT = "d1-v1"

RENDER_JS = """// D1 지연 렌더링 변형: data-c의 base64 HTML을 data-d(ms) 뒤에 그린다. 시험 페이지 전용.
(function () {
  var el = document.getElementById('app')
  if (!el) return
  setTimeout(function () {
    var bin = atob(el.getAttribute('data-c'))
    var bytes = new Uint8Array(bin.length)
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
    el.innerHTML = new TextDecoder('utf-8').decode(bytes)
  }, parseInt(el.getAttribute('data-d'), 10))
})()
"""

NAV_JS = """// D1 스크립트 이동 변형: data-to로 이동한다. 시험 페이지 전용.
(function () {
  var el = document.getElementById('nav')
  setTimeout(function () { location.replace(el.getAttribute('data-to')) }, 300)
})()
"""


def page_id(family: str, variant: str, suffix: str = "") -> str:
    return "p" + hashlib.sha256(f"{SALT}:{family}:{variant}:{suffix}".encode()).hexdigest()[:10]


def params(rng: random.Random, brand: str) -> dict:
    return {
        "brand": brand,
        "amount": f"{rng.randrange(120, 980) * 1000:,}",
        "fee": f"{rng.choice([3000, 9900, 19800, 33000, 55000, 150000]):,}",
        "hours": rng.choice([12, 24, 48]),
        "rate": rng.choice([15, 20, 30, 45]),
        "bonus": rng.choice([10, 20, 30, 50]),
        "code": f"{rng.choice(['WIN', 'VIP', 'GO', 'ACE'])}{rng.randrange(100, 999)}",
        "account": f"{rng.randrange(100, 999)}-{rng.randrange(1000, 9999)}-{rng.randrange(1000, 9999)}",
    }


def html(title: str, body: str, head_extra: str = "") -> str:
    return (
        '<!doctype html>\n<html lang="ko">\n<head><meta charset="utf-8">'
        f"<title>{title}</title>{head_extra}</head>\n<body>\n{body}\n</body>\n</html>\n"
    )


def main() -> None:
    if OUT_HTML.exists():
        shutil.rmtree(OUT_HTML)
    OUT_HTML.mkdir(parents=True)
    (OUT_HTML / "render.js").write_text(RENDER_JS, encoding="utf-8", newline="\n")
    (OUT_HTML / "nav.js").write_text(NAV_JS, encoding="utf-8", newline="\n")

    entries = []
    for fam in FAMILIES:
        rng = random.Random(f"{SALT}:{fam.key}")
        for i, variant in enumerate(fam.variants):
            p = params(rng, fam.brands[i % len(fam.brands)])
            title, body = fam.render(p)
            pid = page_id(fam.key, variant)
            final = f"/d1/{pid}.html"
            if variant == "static":
                (OUT_HTML / f"{pid}.html").write_text(html(title, body), encoding="utf-8", newline="\n")
                entry = final
            elif variant == "delayed":
                encoded = base64.b64encode(body.encode()).decode()
                delay = rng.choice([1200, 1500, 1800, 2000])
                shell = f'<div id="app" data-d="{delay}" data-c="{encoded}"></div>'
                (OUT_HTML / f"{pid}.html").write_text(
                    html(title, shell, '<script src="/d1/render.js" defer></script>'), encoding="utf-8", newline="\n"
                )
                entry = final
            elif variant == "redirect":
                (OUT_HTML / f"{pid}.html").write_text(html(title, body), encoding="utf-8", newline="\n")
                entry = f"/r3/d1/{pid}.html"
            elif variant == "jsnav":
                target = page_id(fam.key, variant, "target")
                (OUT_HTML / f"{target}.html").write_text(html(title, body), encoding="utf-8", newline="\n")
                stub = f'<div id="nav" data-to="/d1/{target}.html">잠시만 기다려 주세요…</div>'
                (OUT_HTML / f"{pid}.html").write_text(
                    html("로딩 중", stub, '<script src="/d1/nav.js" defer></script>'), encoding="utf-8", newline="\n"
                )
                entry, final = f"/d1/{pid}.html", f"/d1/{target}.html"
            else:
                raise ValueError(variant)
            entries.append(
                {
                    "id": pid,
                    "url": entry,
                    "final_path": final,
                    "label": fam.label,
                    "family": fam.key,
                    "variant": variant,
                    "split": fam.split,
                    "note": fam.note,
                }
            )

    OUT_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    OUT_MANIFEST.write_text(
        json.dumps({"salt": SALT, "pages": entries}, ensure_ascii=False, indent=1) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    by = {}
    for e in entries:
        by.setdefault((e["split"], e["label"]), 0)
        by[(e["split"], e["label"])] += 1
    print(f"{len(entries)} pages", dict(sorted(by.items())))


if __name__ == "__main__":
    main()
