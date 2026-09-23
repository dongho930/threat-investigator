import { useCallback, useEffect, useState, type FormEvent } from 'react'

import { ApiError, createCase, listCases, type CaseItem, type CaseStatus } from './api'
import CaseDetail from './CaseDetail'
import ReportImport from './ReportImport'

const SOURCE_LABEL: Record<CaseItem['source'], string> = { manual: '수동', feed: '피드', report: '신고' }

const STATUS_LABEL: Record<CaseStatus, string> = {
  queued: '대기',
  investigating: '조사 중',
  judging: '판정 중',
  review: '검토 필요',
  reported: '보고 완료',
  held: '보류',
  rejected: '제외',
  failed: '실패',
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString('ko-KR', { dateStyle: 'short', timeStyle: 'medium' })
}

export default function App() {
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
        text: result.duplicate ? '이미 등록된 URL입니다. 기존 사건을 표시합니다.' : '사건을 등록했습니다.',
      })
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
      </header>

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

      <ReportImport onImported={() => void refresh()} />

      <section className="card">
        <div className="row">
          <h2>사건 목록</h2>
          <span className="muted">총 {total}건</span>
        </div>
        <table>
          <thead>
            <tr>
              <th>상태</th>
              <th>출처</th>
              <th>URL</th>
              <th>메모</th>
              <th>등록 시각</th>
            </tr>
          </thead>
          <tbody>
            {cases.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
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
                <td className="nowrap">{formatTime(c.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {selected && <CaseDetail item={selected} />}
    </main>
  )
}
