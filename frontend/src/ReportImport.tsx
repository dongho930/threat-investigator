import { useState, type FormEvent } from 'react'

import { ApiError, importReports, type ImportResult } from './api'

// 행 오류는 서버가 사유 코드만 돌려준다. 화면에서 뜻을 붙여 보여 준다.
const ROW_ERROR_LABEL: Record<string, string> = {
  invalid_report_no: '접수번호 형식 오류(영문·숫자·-·_ 64자 이내)',
  duplicate_in_file: '파일 안에서 접수번호 중복',
  invalid_reported_at: '신고일시 형식 오류',
  future_reported_at: '신고일시가 미래',
  note_too_long: '메모가 500자 초과',
  scheme_not_allowed: 'http·https URL이 아님',
  ip_not_allowed: '내부·예약 IP 주소',
  host_not_allowed: '내부용 호스트',
  port_not_allowed: '허용되지 않은 포트',
  userinfo_not_allowed: 'URL에 사용자 정보 포함',
  invalid_url: 'URL 형식 오류',
  invalid_length: 'URL 길이 초과',
}

const MAX_BYTES = 1024 * 1024

export default function ReportImport({ onImported }: { onImported: () => void }) {
  const [file, setFile] = useState<File | null>(null)
  const [result, setResult] = useState<ImportResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    if (!file) return
    setError(null)
    setResult(null)
    if (file.size > MAX_BYTES) {
      setError('파일이 1MB를 넘습니다.')
      return
    }
    setBusy(true)
    try {
      setResult(await importReports(file))
      onImported()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '등록에 실패했습니다.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h2>신고 목록 일괄 등록 (CSV)</h2>
      <p className="muted">
        열: 접수번호, 신고일시, URL, 메모(선택). 같은 URL의 신고는 한 사건으로 묶이고, 같은 파일을 다시
        올려도 신고가 중복되지 않습니다. UTF-8·CP949(Excel) 모두 됩니다.{' '}
        <a href="/report-template.csv" download>
          예시 파일 받기
        </a>
      </p>
      <form onSubmit={onSubmit} className="form">
        <label htmlFor="csv">CSV 파일</label>
        <input id="csv" type="file" accept=".csv,text/csv" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        <button type="submit" disabled={busy || !file}>
          {busy ? '등록 중…' : '일괄 등록'}
        </button>
      </form>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {result && (
        <div className="detail-block" role="status">
          <p>
            전체 {result.total}건 · 새 사건 {result.created} · 기존 사건에 병합 {result.merged} · 이미 등록된 신고{' '}
            {result.duplicate} · 거부 {result.rejected}
          </p>
          {result.errors.length > 0 && (
            <table>
              <thead>
                <tr>
                  <th>행</th>
                  <th>사유</th>
                </tr>
              </thead>
              <tbody>
                {result.errors.map((er) => (
                  <tr key={`${er.row}-${er.code}`}>
                    <td className="nowrap">{er.row}</td>
                    <td>{ROW_ERROR_LABEL[er.code] ?? er.code}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </section>
  )
}
