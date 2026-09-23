export type CaseStatus =
  | 'queued'
  | 'investigating'
  | 'judging'
  | 'review'
  | 'confirmed'
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
  assignee: string | null
  created_at: string
}

export interface CaseList {
  items: CaseItem[]
  total: number
}

export interface CaseCreateResult {
  /** 이미 다른 담당자의 사건이면 null (서버가 내용을 돌려주지 않는다) */
  case: CaseItem | null
  duplicate: boolean
}

export class ApiError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.code = code
  }
}

// CSRF 토큰은 로그인·/me 응답으로 받아 메모리에만 둔다(localStorage에 저장하지 않음).
let csrfToken: string | null = null
let onUnauthenticated: (() => void) | null = null

/** 세션이 끊기면(401) 호출할 함수. App이 로그인 화면으로 돌아가게 한다. */
export function setUnauthenticatedHandler(handler: (() => void) | null): void {
  onUnauthenticated = handler
}

const SAFE_METHODS = new Set(['GET', 'HEAD'])

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? 'GET').toUpperCase()
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (!SAFE_METHODS.has(method) && csrfToken) headers['X-CSRF-Token'] = csrfToken
  const res = await fetch(path, {
    ...init,
    credentials: 'same-origin',
    headers: { ...headers, ...(init?.headers as Record<string, string> | undefined) },
  })
  const body: unknown = res.status === 204 ? null : await res.json().catch(() => null)
  if (!res.ok) {
    const b = (body ?? {}) as { code?: string; detail?: string }
    const code = b.code ?? 'http_error'
    if (res.status === 401 && code === 'unauthenticated') onUnauthenticated?.()
    throw new ApiError(code, b.detail ?? `요청이 실패했습니다 (${res.status})`)
  }
  return body as T
}

export type Role = 'investigator' | 'reviewer' | 'admin'

export interface Me {
  id: string
  username: string
  role: Role
  permissions: string[]
  csrf_token: string
}

export async function login(username: string, password: string): Promise<Me> {
  const me = await request<Me>('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  })
  csrfToken = me.csrf_token
  return me
}

export async function fetchMe(): Promise<Me> {
  const me = await request<Me>('/api/v1/auth/me')
  csrfToken = me.csrf_token
  return me
}

export async function logout(): Promise<void> {
  try {
    await request<null>('/api/v1/auth/logout', { method: 'POST' })
  } finally {
    csrfToken = null
  }
}

export function can(me: Me | null, permission: string): boolean {
  return me?.permissions.includes(permission) ?? false
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

export interface VerdictSignal {
  code: string
  type: string
  weight: number
  strong: boolean
  detail: string
}

export interface VerdictItem {
  id: string
  version: number
  status: 'SUSPICIOUS' | 'BENIGN' | 'UNKNOWN'
  suspected_types: string[]
  /** 시스템 판정의 규칙 근거. 검토자 판정(human)은 빈 객체다. */
  rule_result: { version?: string; reason?: string; scores?: Record<string, number>; signals?: VerdictSignal[] }
  policy_reason: string | null
  decided_by: 'system' | 'human'
  reviewer: string | null
  /** AI 판단 기록. 모델이 쓴 문장은 없고 선택지·신호 코드·오류 코드만 있다. */
  model_result?: ModelResult | null
  created_at: string
}

export interface ModelResult {
  used: boolean
  error: string | null
  injection: string[]
  model?: string
  revision?: string
  site_type?: string
  signals?: string[]
  /** 모델 자체 확신도(보정 전). 악성일 확률이 아니다. */
  confidence?: number | null
  latency_ms?: number
}

export function listVerdicts(caseId: string): Promise<{ items: VerdictItem[] }> {
  return request<{ items: VerdictItem[] }>(`/api/v1/cases/${encodeURIComponent(caseId)}/verdicts`)
}

export interface UserBrief {
  id: string
  username: string
  role: Role
}

export function listInvestigators(): Promise<{ items: UserBrief[] }> {
  return request<{ items: UserBrief[] }>('/api/v1/users?role=investigator')
}

export function assignCase(caseId: string, assigneeId: string): Promise<CaseItem> {
  return request<CaseItem>(`/api/v1/cases/${encodeURIComponent(caseId)}/assign`, {
    method: 'POST',
    body: JSON.stringify({ assignee_id: assigneeId }),
  })
}

export type Decision = VerdictItem['status']

export function reviewCase(
  caseId: string,
  decision: Decision,
  suspectedTypes: string[],
  reason: string,
): Promise<VerdictItem> {
  return request<VerdictItem>(`/api/v1/cases/${encodeURIComponent(caseId)}/review`, {
    method: 'POST',
    body: JSON.stringify({ decision, suspected_types: suspectedTypes, reason }),
  })
}
