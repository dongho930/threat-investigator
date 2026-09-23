# 협업 규칙

## 브랜치와 PR
- `main`은 보호 브랜치: 직접 push 금지, PR + 리뷰 1명 이상 승인 + CI(ci, security) 통과 필수.
- 브랜치 이름: `feat/…`, `fix/…`, `sec/…`(보안 수정), `docs/…`
- PR 하나에 기능 하나. PR 템플릿의 시큐어코딩 체크 항목을 채운다.

## 이슈 라벨
보안 이슈에는 보안약점 분류 라벨을 붙인다. 결과보고서의 "보안약점 대응 실적"은 이 라벨로 집계한다.

| 라벨 | 분류 |
|---|---|
| `sc:입력검증` | 입력데이터 검증 및 표현 |
| `sc:보안기능` | 보안기능 |
| `sc:시간상태` | 시간 및 상태 |
| `sc:에러처리` | 에러처리 |
| `sc:코드오류` | 코드오류 |
| `sc:캡슐화` | 캡슐화 |
| `sc:API오용` | API 오용 |
| `sc:AI` | AI 특화 (프롬프트 인젝션 등) |

## 안전 원칙
- 실제 의심 사이트를 개인 PC 브라우저로 열지 않는다. 개발·시험은 `testsites/`의 가상 페이지로 한다.
- 실제 기관·기업 이름을 시험 페이지에 쓰지 않는다.
- `.env`, API 키, 스크린샷 원본을 커밋하지 않는다.
- 외부 위협정보 서비스에 실제 URL을 제출하지 않는다 (조회 전용, 허가된 시험 URL만).

## 로컬 검사 (PR 전에)
```bash
cd backend && ruff check . && ruff format --check . && pytest
cd worker  && ruff check . && ruff format --check . && pytest
cd frontend && npm run lint && npm run build
```
