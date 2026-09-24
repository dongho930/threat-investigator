// D1 스크립트 이동 변형: data-to로 이동한다. 시험 페이지 전용.
(function () {
  var el = document.getElementById('nav')
  setTimeout(function () { location.replace(el.getAttribute('data-to')) }, 300)
})()
