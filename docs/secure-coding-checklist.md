# 시큐어코딩 체크리스트

기준: 행정안전부 「소프트웨어 보안약점 진단가이드」 7개 분류.
각 항목의 **시험** 칸에 자동 시험 위치를 적고, 구현 주차가 끝나면 **상태**를 갱신한다.
PR 리뷰 때 해당 ID를 체크하고, 보안 이슈에는 같은 분류 라벨(`sc:입력검증` 등)을 붙인다.

상태: ✅ 구현·시험 완료 / 🟡 일부 구현 / ⬜ 예정

## 1. 입력데이터 검증 및 표현 (SC-IN)

| ID | 위험 지점 | 대책 | 시험 | 주차 | 상태 |
|---|---|---|---|---|---|
| SC-IN-01 | 수집한 페이지 제목·텍스트가 콘솔에 표시됨 (저장형 XSS) | React 기본 이스케이프, `dangerouslySetInnerHTML`·`innerHTML` 금지(ESLint), nginx 엄격한 CSP, 의심 URL·수집 URL을 링크로 만들지 않음(사건 상세 화면 포함), 증거 응답 Content-Type 고정 + nosniff | `frontend/eslint.config.js`, `testsites/html/xss-title.html`(2주차 E2E에서 텍스트로만 표시·대화상자 0건 확인) | 1·2·4 | 🟡 |
| SC-IN-02 | 검색·필터 조건 (SQL 삽입) | SQLAlchemy ORM·바인딩만 사용, 원시 SQL 금지 | Semgrep `p/python` | 1 | ✅ |
| SC-IN-03 | 조사 요청 URL (SSRF) | 등록 시 스킴·호스트·IP·포트 검사. Worker: 리다이렉트를 한 단계씩 직접 따라가며 단계마다 검사, 모든 브라우저 요청을 route로 검사. **송신 프록시**: Worker는 인터넷에 직접 닿지 않고(`sandbox` 내부망), 모든 연결이 프록시에서 목적지 IP 검사를 받는다 — route가 못 막는 하위 자원 리다이렉트도 연결 시점에 차단 | `backend/tests/test_url_policy.py`, `worker/tests/test_url_guard.py`, `worker/tests/test_collector_browser.py`, `egress-proxy/tests/`, `testsites /ssrf-*`, `/sub-redirect.html` | 1·2·3 | ✅ |
| SC-IN-04 | 증거 파일명 (경로 조작) | 저장소 키는 서버가 생성한 `<case_id>/<uuid>.<ext>`만 사용, 읽을 때 키 형식·루트 이탈 재검사, 덮어쓰기 금지(`xb`) | `backend/tests/test_evidence_store.py`, `test_storage_key_is_server_generated` | 2 | ✅ |
| SC-IN-07 | Worker가 올리는 증거 파일 | 종류별 Content-Type·PNG 시그니처·JSON 객체 검사, 크기 제한(스트리밍 중 차단), 수집기 버전 헤더 형식 제한 | `test_invalid_evidence_rejected`, `test_oversized_evidence_rejected` | 2 | ✅ |
| SC-IN-05 | URL·페이지 문구의 개행 (로그 삽입) | `safe_log_value`로 제어문자 제거·길이 제한 | `backend/tests/test_logging_and_outbox.py` | 1 | ✅ |
| SC-IN-06 | 모든 API 입력 | Pydantic 스키마, `extra="forbid"`, 길이·범위 제한 | `backend/tests/test_cases_api.py` | 1 | ✅ |

## 2. 보안기능 (SC-SF)

| ID | 위험 지점 | 대책 | 시험 | 주차 | 상태 |
|---|---|---|---|---|---|
| SC-SF-01 | 콘솔 로그인 | Argon2id 해시, 로그인 시도 제한, HttpOnly·Secure·SameSite 쿠키, 세션 만료 | — | 4 | ⬜ |
| SC-SF-02 | 권한 확인 | RBAC(조사자·검토자·관리자), 모든 API에서 서버 측 확인 | — | 4 | ⬜ |
| SC-SF-03 | 다른 사건 접근 (IDOR) | 사건 단위 접근 확인 | — | 4 | ⬜ |
| SC-SF-04 | API 키·DB 비밀번호 | 환경변수로만 주입, `.env` 커밋 금지, gitleaks | `.github/workflows/security.yml` | 1 | ✅ |
| SC-SF-05 | CSRF | 쿠키 인증 도입 시 CSRF 토큰 + SameSite | — | 4 | ⬜ |
| SC-SF-06 | 전송 구간 | 운영 배포 시 TLS 필수, 내부 네트워크 분리 | `compose.yaml` networks | 1·7 | 🟡 |
| SC-SF-07 | Worker 내부 API | 서비스 토큰(32자 이상, `hmac.compare_digest`), `/internal` 경로는 nginx가 404 처리, Worker·backend만 연결된 `api` 네트워크 | `test_internal_api_requires_worker_token`, `test_internal_routes_not_under_public_api_prefix` | 2 | ✅ |
| SC-SF-08 | 증거 무결성 | 저장 시 SHA-256·버전 기록, 조회할 때마다 해시 재대조 후 불일치면 내용 대신 409, 감사 로그 | `test_tampered_evidence_is_not_served` | 2 | ✅ |

## 3. 시간 및 상태 (SC-TS)

| ID | 위험 지점 | 대책 | 시험 | 주차 | 상태 |
|---|---|---|---|---|---|
| SC-TS-01 | 작업 발행 누락·중복 | Outbox 패턴(사건·이벤트 한 트랜잭션), relay 재발행 허용 | `test_publish_pending_marks_published_once` | 1 | ✅ |
| SC-TS-02 | 같은 작업 중복 실행 | Worker 멱등 키(case_id+stage) | — | 3 | ⬜ |
| SC-TS-03 | 동시 등록 경쟁 | `url_sha256` 유니크 제약 + IntegrityError 처리 | `test_duplicate_url_returns_existing` | 1 | ✅ |
| SC-TS-04 | 중복 제출 | `submissions.idempotency_key` 유니크, 전송 시도 ≠ 접수 확인 | — | 6 | ⬜ |

## 4. 에러처리 (SC-EH)

| ID | 위험 지점 | 대책 | 시험 | 주차 | 상태 |
|---|---|---|---|---|---|
| SC-EH-01 | 예외 메시지로 내부 정보 노출 | 공통 예외 처리기, request_id만 응답 | `test_unhandled_error_hides_details` | 1 | ✅ |
| SC-EH-02 | 검증 오류에 입력값 반사 | 422 응답에서 `input` 제거 | `test_unknown_field_rejected_without_echo` | 1 | ✅ |
| SC-EH-03 | 실패를 안전으로 처리 | 조사 실패·시간초과는 BENIGN이 아닌 보류 | — | 4 | ⬜ |
| SC-EH-04 | Worker 실패 보고 | 정해진 사유 코드만 허용(자유 텍스트·예외 원문 거부), route 처리기 예외 시 요청 차단(fail-closed) | `test_free_text_reason_rejected`, `test_collector_crash_reports_code_only` | 2 | ✅ |

## 5. 코드오류 (SC-CE)

| ID | 위험 지점 | 대책 | 시험 | 주차 | 상태 |
|---|---|---|---|---|---|
| SC-CE-01 | 작업 메시지 역직렬화 | JSON + Pydantic만 허용, pickle 금지, 크기 제한, 불량 메시지는 dead-letter | `worker/tests/test_consumer.py` | 1 | ✅ |
| SC-CE-02 | 브라우저·파일 자원 누수 | Playwright·브라우저·컨텍스트를 `with`/`closing`으로 해제, 증거 파일은 임시 파일 후 rename, DB 실패 시 파일 삭제 | `worker/tests/test_collector_browser.py` | 2 | ✅ |

## 6. 캡슐화 (SC-EN)

| ID | 위험 지점 | 대책 | 시험 | 주차 | 상태 |
|---|---|---|---|---|---|
| SC-EN-01 | 디버그·API 문서 노출 | 운영(`ENV=production`)에서 `/api/docs` 비활성화 | — | 1 | ✅ |
| SC-EN-02 | 로그 속 민감정보 | URL 쿼리 값 마스킹(`redact_url`), 쿠키·토큰 기록 금지 | `test_redact_url_masks_query_values` | 1 | ✅ |
| SC-EN-03 | 응답에 내부 필드 노출 | 응답 전용 모델(`CaseOut`) 분리 | `test_create_case_records_audit_and_outbox` | 1 | ✅ |
| SC-EN-04 | 보안 헤더 누락 | nosniff, DENY, CSP, no-store, Referrer-Policy | `test_security_headers` | 1 | ✅ |

## 7. API 오용 (SC-AP)

| ID | 위험 지점 | 대책 | 시험 | 주차 | 상태 |
|---|---|---|---|---|---|
| SC-AP-01 | DNS 결과만 믿는 접근 검사 (DNS 리바인딩) | 송신 프록시가 연결마다 DNS를 **한 번만** 조회해 검사하고, 검사한 IP로 직접 연결(호스트 이름을 다시 넘기지 않음). 조회된 주소가 하나라도 내부면 거부 | `egress-proxy/tests/test_server.py::test_connects_to_checked_ip_and_resolves_once`, `egress-proxy/tests/test_policy.py` (`mixed`, `mapped`) | 2·3 | ✅ |
| SC-AP-02 | 외부 위협정보 API | 타임아웃·재시도 상한·호출 한도, 조회 전용 기본값 | — | 5 | ⬜ |
| SC-AP-03 | 취약한 라이브러리 | 버전 고정, pip-audit·npm audit·Trivy | `.github/workflows/security.yml` | 1 | ✅ |

## AI 특화 (SC-AI)

| ID | 위험 지점 | 대책 | 시험 | 주차 | 상태 |
|---|---|---|---|---|---|
| SC-AI-01 | 프롬프트 인젝션 | 페이지 문구 분리 전달, 모델에 도구 권한 없음, 출력 스키마·허용값 검증, 모델 출력만으로 제보 금지 | `testsites/html/prompt-injection.html` | 5 | ⬜ |
