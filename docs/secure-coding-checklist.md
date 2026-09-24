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
| SC-IN-08 | 신고 CSV 일괄 등록 | 크기(1MB)·행 수(1000) 제한(nginx·서버 이중), UTF-8/CP949만, 필수 열 확인, 행마다 접수번호 형식·신고일시(미래 거부)·메모 길이·URL 정책 검사, 오류는 행 번호·사유 코드만 응답(입력 반사 없음), 접수번호 유니크로 재업로드 멱등 | `backend/tests/test_reports.py` | 3 | ✅ |
| SC-IN-09 | CSV 수식 삽입 (내보내기) | 신고·수집 값을 CSV로 내보낼 때 `=`·`+`·`-`·`@`로 시작하는 칸을 무력화 (저장은 원문, 화면은 텍스트) | `test_formula_like_values_are_stored_as_text` (저장 측) | 3 | ⬜ |
| SC-IN-11 | 실시간 조사 화면·조사 녹화 | 담당자는 이미지(JPEG)·영상(WebM)만 받고 의심 페이지를 직접 열지 않음, 형식(매직 바이트)·Content-Type·크기 검사, 실시간 화면은 사건의 현재 작업·조사 중일 때만 받고 최신 1장만 Redis에 20초(증거 아님), 콘솔 조회는 사건 단위 접근 확인, 녹화는 SHA-256 증거로 저장, 화면 전송 실패는 조사에 영향 없음 | `backend/tests/test_live_and_video.py`, `worker/tests/test_collector_browser.py` | 2 | ✅ |
| SC-IN-10 | 위협정보 피드(외부 목록) 입력 | 공개된 SHA-256 체크섬과 대조해 다르면 그 회차 전체 미등록, 송신 프록시로만 다운로드·리다이렉트 불허·2MB 제한, 한 회 20건·하루 신규 100건 상한, URL마다 등록 정책 검사, 피드 등재는 판정 근거가 아님(격리 조사 증거만 사용), 로그에는 건수만 | `worker/tests/test_feed.py`, `backend/tests/test_feed.py` | 3 | ✅ |
| SC-IN-05 | URL·페이지 문구의 개행 (로그 삽입) | `safe_log_value`로 제어문자 제거·길이 제한 | `backend/tests/test_logging_and_outbox.py` | 1 | ✅ |
| SC-IN-06 | 모든 API 입력 | Pydantic 스키마, `extra="forbid"`, 길이·범위 제한 | `backend/tests/test_cases_api.py` | 1 | ✅ |

## 2. 보안기능 (SC-SF)

| ID | 위험 지점 | 대책 | 시험 | 주차 | 상태 |
|---|---|---|---|---|---|
| SC-SF-01 | 콘솔 로그인 | Argon2id 해시(성공 시 매개변수 갱신), 계정별 시도 제한(15분 5회) + nginx IP별 제한(분당 10회), 없는 계정·틀린 비밀번호·비활성 계정 같은 응답(더미 해시로 시간 차 제거), `__Host-` HttpOnly·Secure·SameSite=Strict 쿠키, DB에는 세션 토큰의 SHA-256만 저장, 유휴 30분·절대 8시간 만료, 로그인마다 새 세션, 비활성화·비밀번호 초기화 시 세션 즉시 종료, 계정 관리는 서버 CLI로만 | `backend/tests/test_auth.py` | 4 | ✅ |
| SC-SF-02 | 권한 확인 | RBAC(조사자·검토자·관리자) 권한표 한 곳(`app/security/rbac.py`), 모든 콘솔 API에 `require(권한)` 의존성, 검토자는 자기가 등록한 사건을 확정할 수 없음(4-eyes), 판정 확정은 새 판정 버전(decided_by=human)으로 쌓음 | `test_rbac.py` (`test_every_console_endpoint_requires_login`, `test_every_console_route_is_covered_by_the_list`, `test_admin_cannot_confirm_own_case`) | 4 | ✅ |
| SC-SF-03 | 다른 사건 접근 (IDOR) | 조사자는 자기가 등록했거나 배정받은 사건만(목록 쿼리 조건과 단건 확인이 같은 규칙), 사건·증거·판정·신고 하위 경로 모두 `AccessibleCase` 확인, 볼 수 없는 사건은 없는 사건과 같은 404, 남의 사건 URL을 다시 등록하면 존재만 알리고 내용은 비움 | `test_rbac.py` (`test_investigator_cannot_see_other_investigators_case`, `test_duplicate_url_from_other_investigator_hides_case`) | 4 | ✅ |
| SC-SF-04 | API 키·DB 비밀번호 | 환경변수로만 주입, `.env` 커밋 금지, gitleaks | `.github/workflows/security.yml` | 1 | ✅ |
| SC-SF-05 | CSRF | 세션마다 다른 CSRF 토큰을 `X-CSRF-Token` 헤더로 대조(콘솔은 메모리에만 보관), SameSite=Strict, 상태 변경 요청의 `Sec-Fetch-Site`가 cross-site·same-site면 인증 전에 거부(로그인 CSRF 포함) | `test_auth.py` (`test_state_change_without_csrf_token_is_rejected`, `test_csrf_token_of_other_session_is_rejected`, `test_cross_site_requests_are_rejected_before_auth`) | 4 | ✅ |
| SC-SF-06 | 전송 구간 | 운영 배포 시 TLS 필수, 내부 네트워크 분리 | `compose.yaml` networks | 1·7 | 🟡 |
| SC-SF-07 | Worker 내부 API | 서비스 토큰(32자 이상, `hmac.compare_digest`), `/internal` 경로는 nginx가 404 처리, Worker·backend만 연결된 `api` 네트워크 | `test_internal_api_requires_worker_token`, `test_internal_routes_not_under_public_api_prefix` | 2 | ✅ |
| SC-SF-08 | 증거 무결성 | 저장 시 SHA-256·버전 기록, 조회할 때마다 해시 재대조 후 불일치면 내용 대신 409, 감사 로그 | `test_tampered_evidence_is_not_served` | 2 | ✅ |
| SC-SF-09 | 조사 브라우저 권한 (샌드박스 탈출) | 비root·`cap_drop: ALL`·읽기 전용·no-new-privileges 컨테이너 + Chromium 자체 샌드박스. seccomp는 Docker 기본 프로필에 네임스페이스 샌드박스용 호출 4개만 추가(고정 커밋에서 생성) | `worker/tests/test_sandbox_config.py`, 컨테이너 안 렌더러 네임스페이스 분리 확인 | 3 | ✅ |

## 3. 시간 및 상태 (SC-TS)

| ID | 위험 지점 | 대책 | 시험 | 주차 | 상태 |
|---|---|---|---|---|---|
| SC-TS-01 | 작업 발행 누락·중복 | Outbox 패턴(사건·이벤트 한 트랜잭션), relay 재발행 허용 | `test_publish_pending_marks_published_once` | 1 | ✅ |
| SC-TS-02 | 같은 작업 중복 실행 | 사건마다 현재 작업 ID만 claim·업로드·완료 가능(이전 작업은 `stale_job`), 증거는 (사건·종류·작업) 유니크로 재업로드 시 기존 것 반환, 완료 재보고는 멱등. 임대 만료·오래된 대기 사건은 스위퍼가 새 작업으로 재발행, 3회 초과 시 `retry_exhausted` 실패 | `backend/tests/test_idempotency.py`, `test_same_job_reupload_is_idempotent`, Docker에서 같은 작업 재전달 → 건너뜀·증거 중복 0 | 3 | ✅ |
| SC-TS-03 | 동시 등록 경쟁 | `url_sha256` 유니크 제약 + IntegrityError 처리 | `test_duplicate_url_returns_existing` | 1 | ✅ |
| SC-TS-04 | 중복 제출 | `submissions.idempotency_key` 유니크, 전송 시도 ≠ 접수 확인 | — | 6 | ⬜ |

## 4. 에러처리 (SC-EH)

| ID | 위험 지점 | 대책 | 시험 | 주차 | 상태 |
|---|---|---|---|---|---|
| SC-EH-01 | 예외 메시지로 내부 정보 노출 | 공통 예외 처리기, request_id만 응답 | `test_unhandled_error_hides_details` | 1 | ✅ |
| SC-EH-02 | 검증 오류에 입력값 반사 | 422 응답에서 `input` 제거 | `test_unknown_field_rejected_without_echo` | 1 | ✅ |
| SC-EH-03 | 실패를 안전으로 처리 | 수집 실패·증거 없음·변조된 증거는 규칙 판정에서 UNKNOWN(보류, `insufficient_evidence`), BENIGN은 온전히 수집했고 징후가 전혀 없을 때만. 재시도 소진은 `failed(retry_exhausted)` | `backend/tests/test_rules.py`, `test_judging_api.py` (`failed_collection_records_unknown_not_benign`, `tampered_evidence_is_not_used_for_judging`) | 2주차 | ✅ |
| SC-EH-04 | Worker 실패 보고 | 정해진 사유 코드만 허용(자유 텍스트·예외 원문 거부), route 처리기 예외 시 요청 차단(fail-closed) | `test_free_text_reason_rejected`, `test_collector_crash_reports_code_only` | 2 | ✅ |

## 5. 코드오류 (SC-CE)

| ID | 위험 지점 | 대책 | 시험 | 주차 | 상태 |
|---|---|---|---|---|---|
| SC-CE-01 | 작업 메시지 역직렬화 | JSON + Pydantic만 허용, pickle 금지, 크기 제한, 불량 메시지는 dead-letter | `worker/tests/test_consumer.py` | 1 | ✅ |
| SC-CE-03 | 수집 자원 고갈(서비스 거부) | 수집 1건을 별도 프로세스 그룹에서 실행하고 전체 시간 제한(60초)을 넘으면 브라우저까지 그룹째 SIGKILL, `collection_timeout`으로 보고 후 다음 작업 진행. 수집기는 자식 프로세스가 직접 만듦(부모 객체를 넘기지 않음) | `worker/tests/test_isolation.py`(손자 프로세스까지 종료 확인), D2-15 대용량 문서 | 2 | ✅ |
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
| SC-AI-01 | 프롬프트 인젝션 | 모델 호출 **전에** 코드가 AI 지시문 형태(역할 표시·채팅 템플릿 토큰·가짜 구분자·지시 무시·판정 덮어쓰기)를 찾으면 그 페이지는 모델에 보내지 않고 보류, 페이지 글은 `<untrusted_page>` 데이터 구역에 JSON으로 넣고 `<`·`>`를 이스케이프(구분자 흉내 차단), 모델에 도구 권한 없음, 출력은 JSON 스키마 강제 + Pydantic 재검증(허용값·추가 필드 거부·크기 제한), 자유 문장은 받지 않음, **모델만으로 SUSPICIOUS 불가**·규칙과 충돌 시 보류 | `backend/tests/test_ai_judge.py` (`test_injection_*`, `test_llm_request_keeps_page_inside_data_block`, `test_model_alone_never_makes_suspicious`, `test_injection_page_is_not_sent_to_model`), `testsites/html/prompt-injection.html` | 2·5 | ✅ |
| SC-AI-02 | 모델 공급망 | 가중치는 커밋 고정 URL + 파일별 SHA-256 검증(빌드 때만 다운로드), 서버 이미지 다이제스트 고정, safetensors·GGUF만(원격 코드·pickle 없음 확인), 실행 중에는 인터넷 없는 `ai` 네트워크·비root·읽기 전용·`HF_HUB_OFFLINE` | `ai/laya/Dockerfile`, `ai/llm/Dockerfile`, Trivy(ai/laya·ai/llm) | 2 | ✅ |
| SC-AI-03 | 모델 장애·지연 | 시간 제한·응답 크기 제한, 실패는 정해진 코드만 기록하고 보류(UNKNOWN), ai-judge가 멈추면 스위퍼가 보류로 넘김, 재조사로 바뀐 사건에 옛 결과를 쓰지 않음 | `test_model_failure_goes_to_hold_not_safe`, `test_sweeper_releases_case_when_ai_judge_is_down`, `test_stale_result_is_not_written_after_reinvestigation`, `test_post_json_*` | 2 | ✅ |
