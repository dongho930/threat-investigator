import { useCallback, useEffect, useState, type FormEvent } from 'react'

import {
  ApiError,
  can,
  createCase,
  fetchMe,
  listCases,
  logout,
  setUnauthenticatedHandler,
  type CaseItem,
  type CaseStatus,
  type Me,
} from './api'
import CaseDetail from './CaseDetail'
import Login from './Login'
import ReportImport from './ReportImport'

const SOURCE_LABEL: Record<CaseItem['source'], string> = { manual: '수동', feed: '피드', report: '신고' }

const STATUS_LABEL: Record<CaseStatus, string> = {
  queued: '대기',
  investigating: '조사 중',
  judging: '판정 중',
  review: '검토 필요',
  confirmed: '확정 (제보 대기)',
  reported: '보고 완료',
  held: '보류',
  rejected: '제외',
  failed: '실패',
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString('ko-KR', { dateStyle: 'short', timeStyle: 'medium' })
}

const ROLE_LABEL: Record<Me['role'], string> = { investigator: '조사자', reviewer: '검토자', admin: '관리자' }

function Console({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [cases, setCases] = useState<CaseItem[]>([])
  const [total, setTotal] = useState(0)
  const [url, setUrl] = useState('')
  const [note, setNote] = useState('')
  const [message, setMessage] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const selected = cases.find((c) => c.id === selectedId) ?? null

  const refresh = useCallback(async () => {
    try {
      const data = await listCases()
      setCases(data.items)
      setTotal(data.total)
    } catch {
      setMessage({ kind: 'error', text: '사건 목록을 불러오지 못했습니다.' })
    }
  }, [])

  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(), 5000)
    return () => window.clearInterval(timer)
  }, [refresh])

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setSubmitting(true)
    setMessage(null)
    try {
      const result = await createCase(url.trim(), note)
      setMessage({
        kind: 'ok',
        text: !result.duplicate
          ? '사건을 등록했습니다.'
          : result.case
            ? '이미 등록된 URL입니다. 기존 사건을 표시합니다.'
            : '이미 다른 담당자가 등록한 URL입니다. 이 사건을 맡으려면 검토자에게 배정을 요청하세요.',
      })
      if (result.case) setSelectedId(result.case.id)
      setUrl('')
      setNote('')
      await refresh()
    } catch (err) {
      const text = err instanceof ApiError ? err.message : '등록에 실패했습니다.'
      setMessage({ kind: 'error', text })
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="container">
      <header>
        <h1>위협 의심 사이트 조사 콘솔</h1>
        <p className="muted">
          결과는 의심 징후에 대한 기술적 평가이며, 법적 판정이나 자동 차단이 아닙니다.
        </p>
        <div className="row userbar">
          <span>
            {me.username} <span className="badge">{ROLE_LABEL[me.role]}</span>
          </span>
          <button type="button" className="link-button" onClick={onLogout}>
            로그아웃
          </button>
        </div>
      </header>

      {can(me, 'case:create') && (
        <section className="card">
          <h2>의심 URL 등록</h2>
          <form onSubmit={onSubmit} className="form">
            <label htmlFor="url">URL</label>
            <input
              id="url"
              type="url"
              required
              maxLength={2048}
              placeholder="https://example.com/login"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
            <label htmlFor="note">메모 (선택)</label>
            <input
              id="note"
              type="text"
              maxLength={500}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              autoComplete="off"
            />
            <button type="submit" disabled={submitting}>
              {submitting ? '등록 중…' : '등록'}
            </button>
          </form>
          {message && (
            <p role="status" className={message.kind === 'ok' ? 'ok' : 'error'}>
              {message.text}
            </p>
          )}
        </section>
      )}

      {can(me, 'report:import') && <ReportImport onImported={() => void refresh()} />}

      <section className="card">
        <div className="row">
          <h2>사건 목록</h2>
          <span className="muted">
            총 {total}건{!can(me, 'case:read_all') && ' (내가 등록했거나 배정받은 사건)'}
          </span>
        </div>
        <table>
          <thead>
            <tr>
              <th>상태</th>
              <th>출처</th>
              <th>URL</th>
              <th>메모</th>
              <th>담당</th>
              <th>등록 시각</th>
            </tr>
          </thead>
          <tbody>
            {cases.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  등록된 사건이 없습니다.
                </td>
              </tr>
            )}
            {cases.map((c) => (
              <tr
                key={c.id}
                className={c.id === selectedId ? 'selected clickable' : 'clickable'}
                onClick={() => setSelectedId(c.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') setSelectedId(c.id)
                }}
                tabIndex={0}
                aria-selected={c.id === selectedId}
              >
                <td>
                  <span className={`badge badge-${c.status}`}>{STATUS_LABEL[c.status]}</span>
                </td>
                <td className="nowrap">{SOURCE_LABEL[c.source]}</td>
                {/* 의심 URL은 링크로 만들지 않는다: 담당자가 실수로 클릭해 직접 접속하는 것을 막는다. */}
                <td className="url">{c.url}</td>
                <td>{c.note ?? ''}</td>
                <td className="nowrap">{c.assignee ?? ''}</td>
                <td className="nowrap">{formatTime(c.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {selected && <CaseDetail item={selected} me={me} onChanged={() => void refresh()} />}
    </main>
  )
}

export default function App() {
  // undefined: 세션 확인 중, null: 로그인 필요
  const [me, setMe] = useState<Me | null | undefined>(undefined)

  useEffect(() => {
    setUnauthenticatedHandler(() => setMe(null))
    fetchMe()
      .then(setMe)
      .catch(() => setMe(null))
    return () => setUnauthenticatedHandler(null)
  }, [])

  async function onLogout() {
    try {
      await logout()
    } finally {
      setMe(null)
    }
  }

  if (me === undefined) return <main className="container muted">불러오는 중…</main>
  if (me === null) return <Login onLogin={setMe} />
  // 계정이 바뀌면 이전 사용자의 화면 상태(선택한 사건 등)를 남기지 않는다.
  return <Console key={me.id} me={me} onLogout={() => void onLogout()} />
}
