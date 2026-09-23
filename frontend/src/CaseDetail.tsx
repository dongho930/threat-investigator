import { useEffect, useState } from 'react'

import {
  ApiError,
  getEvidenceJson,
  listEvidence,
  listReports,
  screenshotUrl,
  type CaseItem,
  type DomSummary,
  type EvidenceItem,
  type NetworkSummary,
  type RedirectHop,
  type ReportItem,
} from './api'

// 수집한 제목·본문·URL은 모두 신뢰하지 않는 데이터다. 텍스트 노드로만 렌더링하고 링크로 만들지 않는다 (SC-IN-01).

const REASON_LABEL: Record<string, string> = {
  blocked_by_policy: '안전 정책에 의해 차단됨',
  too_many_redirects: '리다이렉트 횟수 초과',
  navigation_timeout: '페이지 응답 시간 초과',
  navigation_error: '페이지 접속 실패',
  collector_error: '수집기 오류',
  retry_exhausted: '재시도 한도 초과 (조사 작업이 반복해서 끝나지 않음)',
}

const KIND_LABEL: Record<string, string> = {
  screenshot: '스크린샷',
  dom_summary: '페이지 요약',
  redirect_chain: '이동 경로',
  network_summary: '네트워크 요약',
}

interface Loaded {
  evidence: EvidenceItem[]
  reports: ReportItem[]
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

export default function CaseDetail({ item }: { item: CaseItem }) {
  // 어느 사건의 데이터인지 함께 보관해, 사건을 바꾼 직후 이전 사건의 증거 ID로 요청하지 않게 한다.
  const [data, setData] = useState<(Loaded & { caseId: string }) | null>(null)
  const [failedShotId, setFailedShotId] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const [{ items }, reports] = await Promise.all([
          listEvidence(item.id),
          listReports(item.id).then((r) => r.items),
        ])
        const errors: string[] = []
        const [dom, chain, network] = await Promise.all([
          loadJson<DomSummary>(item.id, latest(items, 'dom_summary'), errors),
          loadJson<{ hops: RedirectHop[] }>(item.id, latest(items, 'redirect_chain'), errors),
          loadJson<NetworkSummary>(item.id, latest(items, 'network_summary'), errors),
        ])
        if (!cancelled) setData({ caseId: item.id, evidence: items, reports, dom, chain, network, errors })
      } catch {
        if (!cancelled) setData({ caseId: item.id, evidence: [], reports: [], errors: ['증거 목록을 불러오지 못했습니다.'] })
      }
    }
    void load()
    return () => {
      cancelled = true
    }
  }, [item.id, item.status])

  const current = data?.caseId === item.id ? data : null
  const shot = current ? latest(current.evidence, 'screenshot') : undefined

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
