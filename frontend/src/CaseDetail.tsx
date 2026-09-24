import { useEffect, useState, type FormEvent } from 'react'

import LiveView from './LiveView'

import {
  ApiError,
  assignCase,
  can,
  fetchReviewDraft,
  getEvidenceJson,
  listInvestigators,
  listEvidence,
  listReports,
  listVerdicts,
  reviewCase,
  screenshotUrl,
  type CaseItem,
  type Decision,
  type DomSummary,
  type EvidenceItem,
  type Me,
  type NetworkSummary,
  type ReviewDraft,
  type RedirectHop,
  type ReportItem,
  type UserBrief,
  type VerdictItem,
} from './api'

// 수집한 제목·본문·URL은 모두 신뢰하지 않는 데이터다. 텍스트 노드로만 렌더링하고 링크로 만들지 않는다 (SC-IN-01).

const REASON_LABEL: Record<string, string> = {
  blocked_by_policy: '안전 정책에 의해 차단됨',
  too_many_redirects: '리다이렉트 횟수 초과',
  navigation_timeout: '페이지 응답 시간 초과',
  navigation_error: '페이지 접속 실패',
  collector_error: '수집기 오류',
  collection_timeout: '수집 시간 제한 초과 (브라우저를 강제로 종료함)',
  retry_exhausted: '재시도 한도 초과 (조사 작업이 반복해서 끝나지 않음)',
}

const KIND_LABEL: Record<string, string> = {
  screenshot: '스크린샷',
  dom_summary: '페이지 요약',
  redirect_chain: '이동 경로',
  network_summary: '네트워크 요약',
  video: '조사 녹화',
}

interface Loaded {
  evidence: EvidenceItem[]
  reports: ReportItem[]
  verdicts: VerdictItem[]
  dom?: DomSummary
  chain?: { hops: RedirectHop[] }
  network?: NetworkSummary
  errors: string[]
}

function latest(items: EvidenceItem[], kind: EvidenceItem['kind']): EvidenceItem | undefined {
  return items.filter((e) => e.kind === kind).sort((a, b) => b.version - a.version)[0]
}

async function loadJson<T>(caseId: string, item: EvidenceItem | undefined, errors: string[]): Promise<T | undefined> {
  if (!item) return undefined
  try {
    return await getEvidenceJson<T>(caseId, item.id)
  } catch (err) {
    const code = err instanceof ApiError ? err.code : 'error'
    errors.push(`${KIND_LABEL[item.kind]}: ${code === 'integrity_mismatch' ? '무결성 검증 실패' : '불러오기 실패'}`)
    return undefined
  }
}

const VERDICT_LABEL: Record<VerdictItem['status'], string> = {
  SUSPICIOUS: '의심 징후 있음',
  UNKNOWN: '판단 보류 (사람 검토 우선)',
  BENIGN: '규칙상 징후 없음',
}

const TYPE_LABEL: Record<string, string> = {
  PHISHING: '피싱',
  SCAM: '사기',
  ILLEGAL_GAMBLING_SUSPECTED: '불법 도박 의심',
  MALWARE: '악성코드',
  OTHER: '기타',
}

const POLICY_LABEL: Record<string, string> = {
  rule_model_agree: '규칙과 AI 판단이 일치',
  rule_model_conflict: '규칙과 AI 판단이 달라 보류',
  model_only_signal: 'AI만 의심해 보류 (AI 단독으로는 의심 판정을 내리지 않음)',
  model_unavailable: 'AI 판단을 받지 못해 보류',
  prompt_injection_suspected: '페이지에 AI 조작 시도 문구가 있어 AI를 쓰지 않음',
  rule_threshold_met: '강한 징후가 기준 이상',
  weak_signals_only: '약한 징후만 있음',
  no_signals: '규칙에 걸린 징후 없음',
  minor_signals_only: '약한 징후 1개뿐 (보류 기준 미달, 근거는 아래 표)',
  insufficient_evidence: '수집 실패·증거 부족 (안전으로 보지 않음)',
}

const DECISION_LABEL: Record<Decision, string> = {
  SUSPICIOUS: '의심 확정 (제보 대기)',
  BENIGN: '정상 — 제외',
  UNKNOWN: '보류',
}

function verdictBadge(status: Decision): string {
  return status === 'SUSPICIOUS' ? 'badge-failed' : status === 'UNKNOWN' ? 'badge-review' : ''
}

function HumanVerdictView({ verdict }: { verdict: VerdictItem }) {
  return (
    <div className="detail-block">
      <h3>
        검토자 판정 v{verdict.version}{' '}
        <span className={`badge ${verdictBadge(verdict.status)}`}>{DECISION_LABEL[verdict.status]}</span>
      </h3>
      <p className="muted">
        {verdict.reviewer ?? '(알 수 없음)'} · {new Date(verdict.created_at).toLocaleString('ko-KR')}
        {verdict.suspected_types.length > 0 &&
          ` · 의심 유형: ${verdict.suspected_types.map((t) => TYPE_LABEL[t] ?? t).join(', ')}`}
      </p>
      <p>사유: {verdict.policy_reason}</p>
    </div>
  )
}

const REVIEW_TYPES = ['PHISHING', 'SCAM', 'ILLEGAL_GAMBLING_SUSPECTED', 'MALWARE', 'OTHER']

const DRAFT_ERROR_LABEL: Record<string, string> = {
  prompt_injection_suspected: '페이지에 AI 조작 시도 문구가 있어 외부 AI에 보내지 않음',
  refusal: 'AI가 답하지 않음',
  schema_violation: 'AI 응답 형식 오류',
  unreachable: 'AI 서비스 연결 실패',
  auth_failed: 'API 키 오류',
  rate_limited: '호출 한도 초과',
}

// AI 검토 보조 초안(참고용). 모델이 쓴 짧은 문장은 텍스트로만 표시하고, 확정은 검토자가 직접 한다.
function DraftView({ caseId }: { caseId: string }) {
  const [draft, setDraft] = useState<ReviewDraft | null>(null)
  useEffect(() => {
    let cancelled = false
    fetchReviewDraft(caseId)
      .then((d) => {
        if (!cancelled) setDraft(d)
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [caseId])
  if (!draft) return null
  return (
    <div className="draft">
      <p>
        <strong>AI 검토 보조 초안</strong> <span className="badge">참고용 · 확정은 검토자</span>{' '}
        <span className="muted">{draft.model}</span>
      </p>
      {draft.suggestion ? (
        <>
          <p>
            제안: {DECISION_LABEL[draft.suggestion.suggested_decision]}
            {draft.suggestion.suspected_types.length > 0 &&
              ` · ${draft.suggestion.suspected_types.map((t) => TYPE_LABEL[t] ?? t).join(', ')}`}
          </p>
          <ul>
            {draft.suggestion.key_points.map((k, i) => (
              <li key={`k${i}`}>{k}</li>
            ))}
          </ul>
          {draft.suggestion.missing_checks.length > 0 && (
            <p className="muted">추가 확인: {draft.suggestion.missing_checks.join(' · ')}</p>
          )}
        </>
      ) : (
        <p className="muted">초안 없음: {DRAFT_ERROR_LABEL[draft.error ?? ''] ?? draft.error}</p>
      )}
    </div>
  )
}

function ReviewPanel({ item, suggested, onDone }: { item: CaseItem; suggested: string[]; onDone: () => void }) {
  const [decision, setDecision] = useState<Decision>('SUSPICIOUS')
  const [types, setTypes] = useState<string[]>(suggested)
  const [reason, setReason] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await reviewCase(item.id, decision, decision === 'SUSPICIOUS' ? types : [], reason)
      setReason('')
      onDone()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '판정을 저장하지 못했습니다.')
    } finally {
      setBusy(false)
    }
  }

  function toggle(t: string) {
    setTypes((prev) => (prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]))
  }

  return (
    <div className="detail-block">
      <h3>판정 확정 (검토자)</h3>
      <DraftView caseId={item.id} />
      <form onSubmit={onSubmit} className="form">
        <fieldset className="choices">
          <legend>결론</legend>
          {(Object.keys(DECISION_LABEL) as Decision[]).map((d) => (
            <label key={d}>
              <input type="radio" name="decision" checked={decision === d} onChange={() => setDecision(d)} />{' '}
              {DECISION_LABEL[d]}
            </label>
          ))}
        </fieldset>
        {decision === 'SUSPICIOUS' && (
          <fieldset className="choices">
            <legend>의심 유형</legend>
            {REVIEW_TYPES.map((t) => (
              <label key={t}>
                <input type="checkbox" checked={types.includes(t)} onChange={() => toggle(t)} /> {TYPE_LABEL[t]}
              </label>
            ))}
          </fieldset>
        )}
        <label htmlFor="review-reason">사유 (필수, 500자 이내)</label>
        <input
          id="review-reason"
          required
          maxLength={500}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          autoComplete="off"
        />
        <button type="submit" disabled={busy || (decision === 'SUSPICIOUS' && types.length === 0)}>
          {busy ? '저장 중…' : '판정 확정'}
        </button>
      </form>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </div>
  )
}

function AssignPanel({ item, onDone }: { item: CaseItem; onDone: () => void }) {
  const [users, setUsers] = useState<UserBrief[]>([])
  const [selected, setSelected] = useState('')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    listInvestigators()
      .then((r) => setUsers(r.items))
      .catch(() => setError('조사자 목록을 불러오지 못했습니다.'))
  }, [])

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    if (!selected) return
    setError(null)
    try {
      await assignCase(item.id, selected)
      onDone()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '배정하지 못했습니다.')
    }
  }

  return (
    <div className="detail-block">
      <h3>담당 조사자 배정</h3>
      <form onSubmit={onSubmit} className="form">
        <label htmlFor="assignee">담당 (현재: {item.assignee ?? '없음'})</label>
        <select id="assignee" value={selected} onChange={(e) => setSelected(e.target.value)}>
          <option value="">선택</option>
          {users.map((u) => (
            <option key={u.id} value={u.id}>
              {u.username}
            </option>
          ))}
        </select>
        <button type="submit" disabled={!selected}>
          배정
        </button>
      </form>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </div>
  )
}

const SITE_LABEL: Record<string, string> = { phishing: '피싱', scam: '사기', gambling: '불법 도박', normal: '해당 없음' }

const MODEL_ERROR_LABEL: Record<string, string> = {
  timeout: '응답 시간 초과',
  unreachable: '모델 서버 연결 실패',
  schema_violation: '허용되지 않은 형식으로 답함',
  invalid_output: '응답 형식 오류',
  judge_timeout: 'AI 판정 처리기가 응답하지 않음',
  model_disabled: 'AI 판정 꺼짐',
}

function policyText(reason: string | null): string {
  if (!reason) return ''
  const [base = '', extra] = reason.split('+')
  const text = POLICY_LABEL[base] ?? base
  return extra === 'model_abstained' ? `${text} (AI 확신도가 낮아 AI 판단은 반영 안 함)` : text
}

function ModelView({ result }: { result: NonNullable<VerdictItem['model_result']> }) {
  if (result.injection.length > 0) {
    return <p className="muted">AI 모델: 사용 안 함 — 조작 시도 문구 탐지({result.injection.join(', ')})</p>
  }
  if (result.error) {
    return <p className="muted">AI 모델: {MODEL_ERROR_LABEL[result.error] ?? result.error} → 보류</p>
  }
  return (
    <p className="muted">
      AI 모델 {result.model} · 판단: {SITE_LABEL[result.site_type ?? ''] ?? result.site_type}
      {result.signals && result.signals.length > 0 && ` · 신호: ${result.signals.join(', ')}`}
      {result.confidence != null && ` · 모델 자체 확신도 ${result.confidence.toFixed(2)} (보정 전, 악성일 확률 아님)`}
    </p>
  )
}

function VerdictView({ verdict }: { verdict: VerdictItem }) {
  const badge = verdictBadge(verdict.status)
  const signals = verdict.rule_result.signals ?? []
  return (
    <div className="detail-block">
      <h3>
        시스템 판정 v{verdict.version} <span className={`badge ${badge}`}>{VERDICT_LABEL[verdict.status]}</span>
      </h3>
      <p className="muted">
        규칙 {verdict.rule_result.version} · {policyText(verdict.policy_reason)}
        {verdict.suspected_types.length > 0 &&
          ` · 의심 유형: ${verdict.suspected_types.map((t) => TYPE_LABEL[t] ?? t).join(', ')}`}
        {' '}— 기술적 평가이며 최종 결론은 담당자가 내립니다.
      </p>
      {verdict.model_result && <ModelView result={verdict.model_result} />}
      {signals.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>유형</th>
              <th>근거</th>
              <th>강도</th>
            </tr>
          </thead>
          <tbody>
            {signals.map((s) => (
              <tr key={s.code}>
                <td className="nowrap">{TYPE_LABEL[s.type] ?? s.type}</td>
                <td>{s.detail}</td>
                <td className="nowrap">{s.strong ? '강함' : '약함'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

const REVIEWABLE = new Set<CaseItem['status']>(['review', 'held'])

export default function CaseDetail({ item, me, onChanged }: { item: CaseItem; me: Me; onChanged: () => void }) {
  // 어느 사건의 데이터인지 함께 보관해, 사건을 바꾼 직후 이전 사건의 증거 ID로 요청하지 않게 한다.
  const [data, setData] = useState<(Loaded & { caseId: string }) | null>(null)
  const [failedShotId, setFailedShotId] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const [{ items }, reports, verdicts] = await Promise.all([
          listEvidence(item.id),
          listReports(item.id).then((r) => r.items),
          listVerdicts(item.id).then((r) => r.items),
        ])
        const errors: string[] = []
        const [dom, chain, network] = await Promise.all([
          loadJson<DomSummary>(item.id, latest(items, 'dom_summary'), errors),
          loadJson<{ hops: RedirectHop[] }>(item.id, latest(items, 'redirect_chain'), errors),
          loadJson<NetworkSummary>(item.id, latest(items, 'network_summary'), errors),
        ])
        if (!cancelled) setData({ caseId: item.id, evidence: items, reports, verdicts, dom, chain, network, errors })
      } catch {
        if (!cancelled) setData({ caseId: item.id, evidence: [], reports: [], verdicts: [], errors: ['증거 목록을 불러오지 못했습니다.'] })
      }
    }
    void load()
    return () => {
      cancelled = true
    }
  }, [item.id, item.status, item.assignee])

  const current = data?.caseId === item.id ? data : null
  const shot = current ? latest(current.evidence, 'screenshot') : undefined
  const video = current ? latest(current.evidence, 'video') : undefined
  const investigating = item.status === 'queued' || item.status === 'investigating'
  // 판정 이력은 최신 버전이 먼저 온다. 시스템 판정과 검토자 판정을 따로 보여 준다.
  const systemVerdict = current?.verdicts.find((v) => v.decided_by === 'system')
  const humanVerdict = current?.verdicts.find((v) => v.decided_by === 'human')

  return (
    <section className="card">
      <h2>사건 상세</h2>
      <p className="url">{item.url}</p>
      {item.status_reason && (
        <p className="error">실패 사유: {REASON_LABEL[item.status_reason] ?? item.status_reason}</p>
      )}
      {!current && <p className="muted">불러오는 중…</p>}
      {current?.errors.map((e) => (
        <p key={e} className="error">
          {e}
        </p>
      ))}
      {humanVerdict && <HumanVerdictView verdict={humanVerdict} />}
      {systemVerdict && <VerdictView verdict={systemVerdict} />}
      {current && can(me, 'case:review') && REVIEWABLE.has(item.status) && (
        <ReviewPanel key={item.id} item={item} suggested={systemVerdict?.suspected_types ?? []} onDone={onChanged} />
      )}
      {can(me, 'case:assign') && <AssignPanel item={item} onDone={onChanged} />}
      {current && current.reports.length > 0 && (
        <div className="detail-block">
          <h3>접수된 신고 {current.reports.length}건</h3>
          <table>
            <thead>
              <tr>
                <th>접수번호</th>
                <th>신고일시</th>
                <th>신고된 URL</th>
                <th>메모</th>
              </tr>
            </thead>
            <tbody>
              {current.reports.map((r) => (
                <tr key={r.report_no}>
                  <td className="nowrap">{r.report_no}</td>
                  <td className="nowrap">{new Date(r.reported_at).toLocaleString('ko-KR')}</td>
                  <td className="url">{r.url_reported}</td>
                  <td>{r.note ?? ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {current && current.evidence.length === 0 && <p className="muted">아직 수집된 증거가 없습니다.</p>}

      {investigating && <LiveView caseId={item.id} />}

      {video && (
        <div className="detail-block">
          <h3>조사 녹화</h3>
          {/* 격리 브라우저 화면을 녹화한 영상이다. 파일은 서버가 SHA-256으로 검증해 돌려준다. */}
          <video className="screenshot" controls preload="metadata" src={screenshotUrl(item.id, video.id)} />
          <p className="muted">리다이렉트·지연 렌더링·팝업 차단 등 조사 과정 전체 (SHA-256 {video.sha256.slice(0, 12)}…)</p>
        </div>
      )}

      {shot && (
        <div className="detail-block">
          <h3>스크린샷</h3>
          {failedShotId === shot.id ? (
            <p className="error">스크린샷을 표시할 수 없습니다 (무결성 검증 실패 또는 파일 없음).</p>
          ) : (
            <img
              className="screenshot"
              src={screenshotUrl(item.id, shot.id)}
              alt="격리 브라우저에서 찍은 페이지 화면"
              onError={() => setFailedShotId(shot.id)}
            />
          )}
        </div>
      )}

      {current?.chain && (
        <div className="detail-block">
          <h3>이동 경로</h3>
          <ol className="hops">
            {current.chain.hops.map((h, i) => (
              <li key={i}>
                <span className="url">{h.url}</span>{' '}
                {h.blocked ? (
                  <span className="badge badge-failed">차단: {h.blocked}</span>
                ) : (
                  <span className="badge">{h.status}</span>
                )}
              </li>
            ))}
          </ol>
        </div>
      )}

      {current?.dom && (
        <div className="detail-block">
          <h3>페이지 요약</h3>
          <dl className="facts">
            <dt>제목</dt>
            <dd>{current.dom.title}</dd>
            <dt>최종 URL</dt>
            <dd className="url">{current.dom.final_url}</dd>
            <dt>비밀번호 입력칸</dt>
            <dd>{current.dom.password_inputs}개</dd>
            <dt>폼</dt>
            <dd>
              {current.dom.forms.length === 0
                ? '없음'
                : current.dom.forms.map((f, i) => (
                    <div key={i}>
                      {f.method.toUpperCase()} → {f.action_host || '(현재 페이지)'} · 입력:{' '}
                      {f.inputs.map((inp) => `${inp.name || inp.placeholder || '?'}(${inp.type})`).join(', ')}
                    </div>
                  ))}
            </dd>
          </dl>
          <pre className="excerpt">{current.dom.text_excerpt}</pre>
        </div>
      )}

      {current?.network && (
        <div className="detail-block">
          <h3>네트워크 요약</h3>
          <p>
            요청 {current.network.requests}건 · 차단{' '}
            {Object.entries(current.network.blocked)
              .map(([k, v]) => `${k} ${v}`)
              .join(', ') || '없음'}{' '}
            · 팝업 차단 {current.network.popups_blocked}건
          </p>
          <p className="muted">접속 호스트: {Object.keys(current.network.hosts).join(', ') || '없음'}</p>
        </div>
      )}

      {current && current.evidence.length > 0 && (
        <div className="detail-block">
          <h3>증거 무결성 (SHA-256)</h3>
          <table>
            <tbody>
              {current.evidence.map((e) => (
                <tr key={e.id}>
                  <td className="nowrap">
                    {KIND_LABEL[e.kind]} v{e.version}
                  </td>
                  <td className="hash">{e.sha256}</td>
                  <td className="nowrap muted">{(e.size_bytes / 1024).toFixed(1)} KB</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
