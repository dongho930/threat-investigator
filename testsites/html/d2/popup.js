// D2-10: 열자마자 새 창 두 개(외부·메타데이터 주소)를 연다. Worker는 새 창을 닫고 센다.
window.open('http://testsites:8080/d1/render.js')
window.open('http://169.254.169.254/latest/meta-data/')
