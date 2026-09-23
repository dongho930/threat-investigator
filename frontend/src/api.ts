export type CaseStatus =
  | 'queued'
  | 'investigating'
  | 'judging'
  | 'review'
  | 'reported'
  | 'held'
  | 'rejected'
  | 'failed'

export interface CaseItem {
  id: string
  url: string
  host: string
  source: 'manual' | 'feed' | 'report'
  status: CaseStatus
  status_reason: string | null
  note: string | null
  created_at: string
}

export interface CaseList {
  items: CaseItem[]
  total: number
}

export interface CaseCreateResult {
  case: CaseItem
  duplicate: boolean
}

export class ApiError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.code = code
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  const body: unknown = await res.json().catch(() => null)
  if (!res.ok) {
    const b = (body ?? {}) as { code?: string; detail?: string }
    throw new ApiError(b.code ?? 'http_error', b.detail ?? `요청이 실패했습니다 (${res.status})`)
  }
  return body as T
}

export function listCases(limit = 50): Promise<CaseList> {
  return request<CaseList>(`/api/v1/cases?limit=${encodeURIComponent(String(limit))}`)
}

export function createCase(url: string, note: string): Promise<CaseCreateResult> {
  return request<CaseCreateResult>('/api/v1/cases', {
    method: 'POST',
    body: JSON.stringify({ url, note: note.trim() === '' ? null : note }),
  })
}

export type EvidenceKind = 'screenshot' | 'dom_summary' | 'redirect_chain' | 'network_summary'

export interface EvidenceItem {
  id: string
  kind: EvidenceKind
  version: number
  sha256: string
  size_bytes: number
  collector_version: string
  collected_at: string
}

export interface RedirectHop {
  url: string
  status: number | null
  blocked: string | null
}

export interface FormSummary {
  action_host: string
  method: string
  inputs: { type: string; name: string; placeholder: string }[]
}

export interface DomSummary {
  final_url: string
  title: string
  text_excerpt: string
  forms: FormSummary[]
  password_inputs: number
  iframes: number
  links: number
  meta_refresh: string
}

export interface NetworkSummary {
  requests: number
  blocked: Record<string, number>
  hosts: Record<string, number>
  popups_blocked: number
  navigations: string[]
  subresource_redirects: { url: string; violation: string | null }[]
}

function evidencePath(caseId: string, evidenceId?: string): string {
  const base = `/api/v1/cases/${encodeURIComponent(caseId)}/evidence`
  return evidenceId ? `${base}/${encodeURIComponent(evidenceId)}/content` : base
}

export function listEvidence(caseId: string): Promise<{ items: EvidenceItem[] }> {
  return request<{ items: EvidenceItem[] }>(evidencePath(caseId))
}

/** 서버가 SHA-256을 다시 대조한 뒤 돌려준 JSON 증거. 무결성 실패 시 ApiError(integrity_mismatch). */
export function getEvidenceJson<T>(caseId: string, evidenceId: string): Promise<T> {
  return request<T>(evidencePath(caseId, evidenceId))
}

export function screenshotUrl(caseId: string, evidenceId: string): string {
  return evidencePath(caseId, evidenceId)
}

export interface ImportResult {
  batch_id: string
  total: number
  created: number
  merged: number
  duplicate: number
  rejected: number
  errors: { row: number; code: string }[]
}

export interface ReportItem {
  report_no: string
  reported_at: string
  url_reported: string
  note: string | null
  batch_id: string
  created_at: string
}

/** 신고 목록 CSV 파일을 그대로 보낸다. 파싱·검증은 서버가 한다. */
export function importReports(file: File): Promise<ImportResult> {
  return request<ImportResult>('/api/v1/reports/import', {
    method: 'POST',
    body: file,
    headers: { 'Content-Type': 'text/csv' },
  })
}

export function listReports(caseId: string): Promise<{ items: ReportItem[] }> {
  return request<{ items: ReportItem[] }>(`/api/v1/cases/${encodeURIComponent(caseId)}/reports`)
}
