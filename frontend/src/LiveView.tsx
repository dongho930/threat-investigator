import { useEffect, useState } from 'react'

import { fetchLiveFrame } from './api'

// 격리 브라우저의 최신 화면(JPEG)을 이미지로만 받아 보여 준다. 담당자 브라우저는 의심 페이지를 직접 열지 않는다.
export default function LiveView({ caseId }: { caseId: string }) {
  const [src, setSrc] = useState<string | null>(null)
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null)

  useEffect(() => {
    let cancelled = false
    let current: string | null = null
    async function tick() {
      try {
        const blob = await fetchLiveFrame(caseId)
        if (cancelled || !blob) return
        const url = URL.createObjectURL(blob)
        if (current) URL.revokeObjectURL(current)
        current = url
        setSrc(url)
        setUpdatedAt(new Date())
      } catch {
        // 일시적인 오류는 다음 주기에 다시 시도한다
      }
    }
    void tick()
    const timer = window.setInterval(() => void tick(), 700)
    return () => {
      cancelled = true
      window.clearInterval(timer)
      if (current) URL.revokeObjectURL(current)
    }
  }, [caseId])

  return (
    <div className="detail-block">
      <h3>
        실시간 조사 화면 <span className="badge badge-review">격리 브라우저</span>
      </h3>
      {src ? (
        <>
          <img className="screenshot" src={src} alt="격리 브라우저의 현재 화면" />
          <p className="muted">
            {updatedAt?.toLocaleTimeString('ko-KR')} 기준 · 이미지로만 전달되며 이 화면에서는 페이지를 조작할 수 없습니다.
          </p>
        </>
      ) : (
        <p className="muted">격리 브라우저가 페이지를 여는 중입니다…</p>
      )}
    </div>
  )
}
