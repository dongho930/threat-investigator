import { useState, type FormEvent } from 'react'

import { ApiError, login, type Me } from './api'

export default function Login({ onLogin }: { onLogin: (me: Me) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const me = await login(username, password)
      setPassword('')
      onLogin(me)
    } catch (err) {
      // 서버는 없는 계정·틀린 비밀번호를 구분하지 않는다. 화면도 서버 문구를 그대로 보여 준다.
      setError(err instanceof ApiError ? err.message : '로그인에 실패했습니다.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="container narrow">
      <header>
        <h1>위협 의심 사이트 조사 콘솔</h1>
        <p className="muted">허가된 담당자만 사용할 수 있습니다.</p>
      </header>
      <section className="card">
        <h2>로그인</h2>
        <form onSubmit={onSubmit} className="form">
          <label htmlFor="username">아이디</label>
          <input
            id="username"
            required
            maxLength={64}
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <label htmlFor="password">비밀번호</label>
          <input
            id="password"
            type="password"
            required
            maxLength={128}
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button type="submit" disabled={busy}>
            {busy ? '확인 중…' : '로그인'}
          </button>
        </form>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
      </section>
    </main>
  )
}
