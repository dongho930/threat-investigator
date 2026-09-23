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
  source: 'manual' | 'feed'
  status: CaseStatus
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
