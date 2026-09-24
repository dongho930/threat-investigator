// D2-12: Service Worker 등록 시도. 결과를 본문에 적어 증거(페이지 요약)로 확인한다.
var out = document.getElementById('sw')
if (!('serviceWorker' in navigator)) {
  out.textContent = 'SW:unavailable'
} else {
  navigator.serviceWorker.register('/d2/sw.js').then(
    function () { out.textContent = 'SW:registered' },
    function () { out.textContent = 'SW:rejected' }
  )
}
