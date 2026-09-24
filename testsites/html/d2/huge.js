// D2-15: 약 40MB 글자와 2만 개 요소를 만든다. Worker는 제한 안에서 요약만 남기고 끝나야 한다.
var chunk = new Array(2001).join('가나다라마바사아자차카타파하 ')
var parts = []
for (var i = 0; i < 1400; i++) parts.push(chunk)
document.getElementById('big').textContent = parts.join('\n')
for (var j = 0; j < 20000; j++) {
  var d = document.createElement('input')
  d.name = 'field' + j
  document.body.appendChild(d)
}
