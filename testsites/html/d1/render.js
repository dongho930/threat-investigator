// D1 지연 렌더링 변형: data-c의 base64 HTML을 data-d(ms) 뒤에 그린다. 시험 페이지 전용.
(function () {
  var el = document.getElementById('app')
  if (!el) return
  setTimeout(function () {
    var bin = atob(el.getAttribute('data-c'))
    var bytes = new Uint8Array(bin.length)
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
    el.innerHTML = new TextDecoder('utf-8').decode(bytes)
  }, parseInt(el.getAttribute('data-d'), 10))
})()
