"""D1 자체 시험 페이지의 템플릿 계열(기획서 2.6절).

- 가상 브랜드만 쓴다(실제 기관·회사 이름 없음). 입력 폼은 전송되지 않는다(onsubmit에서 막음).
- 의심 유형(피싱·사기·불법 도박)마다 6계열, 정상 대조 10계열.
- 계열마다 개발용(dev)/평가용(eval)을 정해, 같은 계열의 변형이 양쪽에 섞이지 않게 한다.
- 정상 대조는 로그인·결제·환급·베팅 안내처럼 의심 유형과 헷갈리기 쉬운 화면으로 만든다.

각 계열은 (params) -> (title, body_html) 함수다. params에는 변형마다 다른 브랜드·금액·기한이 들어간다.
"""

from collections.abc import Callable
from dataclasses import dataclass

Render = Callable[[dict], tuple[str, str]]


@dataclass(frozen=True)
class Family:
    key: str
    label: str  # phishing | scam | gambling | normal
    split: str  # dev | eval
    variants: tuple[str, ...]
    brands: tuple[str, ...]
    render: Render
    note: str


def _form(fields: list[tuple[str, str, str]], button: str) -> str:
    rows = "".join(
        f'<label>{label} <input name="{name}" type="{typ}" autocomplete="off"></label><br>'
        for label, name, typ in fields
    )
    return f'<form onsubmit="return false">{rows}<button>{button}</button></form>'


# ---------------- 피싱 ----------------


def p_bank_security(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 인터넷뱅킹 - 보안 인증",
        f"<h2>{p['brand']}</h2><h1>전자금융 보안 강화 안내</h1>"
        f"<p>고객님의 계정에서 비정상 접속이 감지되어 이용이 일시 제한되었습니다. {p['hours']}시간 이내에 본인 확인을 "
        "완료하지 않으면 모든 거래가 정지됩니다.</p>"
        + _form(
            [
                ("아이디", "userid", "text"),
                ("비밀번호", "password", "password"),
                ("보안카드 번호", "security_card", "text"),
                ("OTP 번호", "otp", "text"),
            ],
            "본인 확인",
        ),
    )


def p_card_payment(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 결제 승인 오류",
        f"<h1>{p['brand']} 결제 승인이 거절되었습니다</h1>"
        f"<p>최근 결제 {p['amount']}원이 카드 정보 불일치로 승인되지 않았습니다. 카드 정보를 다시 입력하시면 재승인됩니다.</p>"
        + _form(
            [
                ("카드번호", "card_number", "text"),
                ("유효기간", "expiry", "text"),
                ("CVC", "cvc", "password"),
                ("카드 비밀번호 앞 2자리", "card_pin", "password"),
            ],
            "재승인 요청",
        ),
    )


def p_customs(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 통관 보류 안내",
        f"<h1>{p['brand']} 해외 배송 통관 보류</h1>"
        f"<p>개인통관 정보 불일치로 물품이 세관에 보류되었습니다. 오늘 중으로 정보를 확인하지 않으면 반송 처리됩니다.</p>"
        + _form(
            [
                ("이름", "name", "text"),
                ("주민등록번호", "ssn", "text"),
                ("휴대폰 번호", "phone", "tel"),
                ("관세 결제 카드번호", "card_number", "text"),
                ("CVC", "cvc", "password"),
            ],
            "통관 정보 확인",
        ),
    )


def p_webmail(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 계정 확인",
        f"<h1>{p['brand']} 저장 공간이 가득 찼습니다</h1>"
        "<p>새 메일을 받을 수 없습니다. 계정 소유자 확인 후 무료로 저장 공간이 늘어납니다. 확인하지 않으면 계정이 삭제될 수 "
        "있습니다.</p>"
        + _form(
            [
                ("메일 주소", "email", "email"),
                ("비밀번호", "password", "password"),
                ("비밀번호 확인", "password2", "password"),
            ],
            "계정 확인",
        ),
    )


def p_gov_cert(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 공동인증서 갱신",
        f"<h1>{p['brand']} 인증서 만료 예정</h1>"
        f"<p>고객님의 공동인증서가 {p['hours']}시간 후 만료됩니다. 갱신하지 않으면 민원 서비스 이용이 제한됩니다.</p>"
        + _form(
            [("이름", "name", "text"), ("주민등록번호", "ssn", "text"), ("인증서 비밀번호", "cert_pw", "password")],
            "인증서 갱신",
        ),
    )


def p_crypto_wallet(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 지갑 동기화",
        f"<h1>{p['brand']} 지갑 보안 점검</h1>"
        "<p>보안 업데이트로 지갑 동기화가 필요합니다. 복구 문구 12단어와 2단계 인증 코드를 입력하세요. 미완료 시 출금이 "
        "제한됩니다.</p>"
        + _form([("복구 문구(12단어)", "seed_phrase", "text"), ("2단계 인증 코드", "otp", "text")], "동기화"),
    )


# ---------------- 사기 ----------------


def s_tax_refund(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 미수령 환급금 조회",
        f"<h1>{p['brand']}</h1><p>미수령 환급금 {p['amount']}원이 확인되었습니다.</p>"
        f"<p>환급 처리 수수료 {p['fee']}원을 아래 계좌로 먼저 입금해 주세요. 오늘 자정까지 입금하지 않으면 환급이 "
        f"취소됩니다.</p><p>입금 계좌: 가상은행 {p['account']} (예금주: 환급처리센터)</p>",
    )


def s_investment(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} VIP 리딩방",
        f"<h1>{p['brand']} VIP 투자 리딩방</h1>"
        f"<p>원금 보장, 월 수익률 {p['rate']}% 확정! 전문가가 매일 종목을 알려드립니다.</p>"
        f"<p>가입비 {p['fee']}원 입금 후 카카오톡 오픈채팅으로 입장 코드를 받으세요.</p>"
        f"<p>입금 계좌: 가상은행 {p['account']}</p>",
    )


def s_loan_fee(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 대출 승인 안내",
        f"<h1>{p['brand']} 저금리 대출 승인 완료</h1>"
        f"<p>신청하신 {p['amount']}원 대출이 승인되었습니다. 신용 보증료 {p['fee']}원을 입금하시면 즉시 지급됩니다.</p>"
        f"<p>보증료 입금 계좌: 가상은행 {p['account']} · 담당자 텔레그램 상담</p>",
    )


def s_delivery_fee(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 재배송 신청",
        f"<h1>{p['brand']} 배송 실패 안내</h1>"
        f"<p>주소 불일치로 배송이 보류되었습니다. 재배송 수수료 {p['fee']}원을 계좌로 이체해 주세요. 24시간 이내 미이체 시 "
        f"반송됩니다.</p><p>이체 계좌: 가상은행 {p['account']}</p>",
    )


def s_prize(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 경품 당첨",
        f"<h1>축하합니다! {p['brand']} 경품 이벤트 1등 당첨</h1>"
        f"<p>최신 노트북 수령을 위해 제세공과금 {p['fee']}원을 입금해 주세요. 오늘 중 입금하지 않으면 당첨이 취소됩니다.</p>"
        f"<p>입금 계좌: 가상은행 {p['account']} (예금주: 이벤트사무국)</p>",
    )


def s_job(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 재택 부업 모집",
        f"<h1>{p['brand']} 하루 1시간 고수익 부업</h1>"
        f"<p>구매 대행 업무로 건당 수수료 {p['rate']}% 확정 지급. 첫 업무 전 보증금 {p['fee']}원을 입금하면 바로 "
        f"시작할 수 있습니다.</p><p>보증금 계좌: 가상은행 {p['account']} · 라인 상담</p>",
    )


# ---------------- 불법 도박 ----------------


def g_toto(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} - 스포츠 실시간",
        f"<h1>{p['brand']}</h1><p>국내 최고 배당률! 축구·야구·농구 실시간 베팅</p>"
        f"<p>첫충 {p['bonus']}% · 매충 5% · 1:1 충전·환전 24시간</p><p>가입코드: {p['code']}</p>",
    )


def g_casino(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 라이브 카지노",
        f"<h1>{p['brand']} 라이브 카지노</h1><p>바카라·블랙잭 실시간 딜러. 신규 가입 머니 {p['bonus']}만원 지급</p>"
        "<p>충전 즉시 게임 가능, 환전 5분 이내 처리. 먹튀 없는 안전 놀이터</p>",
    )


def g_slot(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 슬롯",
        f"<h1>{p['brand']} 슬롯 무제재</h1><p>인기 슬롯 300종, 롤링 100% · 첫충 {p['bonus']}%</p>"
        "<p>입금 계좌는 고객센터 텔레그램으로 문의하세요. 충전·환전 무제한</p>",
    )


def g_minigame(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 파워볼",
        f"<h1>{p['brand']} 미니게임</h1><p>파워볼·사다리 5분 단위 배팅, 배당률 1.95</p>"
        f"<p>입플 이벤트 {p['bonus']}% · 가입코드 {p['code']} · 환전 신청은 마이페이지</p>",
    )


def g_horse(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 경마",
        f"<h1>{p['brand']} 실시간 경마·경륜</h1><p>해외 경마 전 경주 배팅 가능, 한도 없음</p>"
        f"<p>충전 보너스 {p['bonus']}% · 환전 24시간 · 텔레그램 상담</p>",
    )


def g_invite(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 가입 안내",
        f"<h1>{p['brand']} 보증 놀이터 가입 안내</h1><p>먹튀 검증 완료 · 보증금 1억 예치</p>"
        f"<p>토토·카지노·슬롯 통합 머니. 가입코드 {p['code']} 입력 시 가입 머니 지급, 첫충 {p['bonus']}%</p>",
    )


# ---------------- 정상 대조 ----------------


def n_bank_login(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 개인 인터넷뱅킹 로그인",
        f"<h1>{p['brand']} 인터넷뱅킹</h1>"
        + _form([("아이디", "userid", "text"), ("비밀번호", "password", "password")], "로그인")
        + "<p>보안 안내: 당행은 어떤 경우에도 보안카드 번호 전체나 OTP를 전화·문자로 요구하지 않습니다.</p>"
        "<p>영업시간 안내 · 개인정보처리방침 · 전자금융거래 이용약관</p>",
    )


def n_checkout(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 주문/결제",
        f"<h1>{p['brand']} 주문서</h1><p>주문 상품: 무선 이어폰 1개 · 결제 금액 {p['amount']}원 · 배송비 무료</p>"
        + _form(
            [
                ("받는 분", "receiver", "text"),
                ("주소", "address", "text"),
                ("카드번호", "card_number", "text"),
                ("유효기간", "expiry", "text"),
            ],
            "결제하기",
        )
        + "<p>교환·반품 안내 · 판매자 정보 · 구매 안전 서비스 가입 사업자</p>",
    )


def n_refund_info(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 지방세 환급 안내",
        f"<h1>{p['brand']} 지방세 환급금 안내</h1>"
        "<p>과오납된 지방세 환급금은 본인 명의 계좌로만 지급되며, 수수료나 선입금을 요구하지 않습니다.</p>"
        "<p>환급금 조회는 공식 민원 누리집에서 공동인증서로 로그인해 확인하세요. 문자로 받은 인터넷 주소는 누르지 마세요.</p>",
    )


def n_tracking(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 배송 조회",
        f"<h1>{p['brand']} 배송 조회</h1>"
        + _form([("운송장 번호", "invoice", "text")], "조회")
        + "<p>배송 상태: 간선 하차 → 배송 출발 예정 · 고객센터 운영시간 평일 9~18시</p>",
    )


def n_legal_lottery(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 이용 안내",
        f"<h1>{p['brand']} 공식 이용 안내</h1>"
        "<p>체육진흥투표권은 법에 따라 허가된 발행 사업자만 판매합니다. 1회 구매 한도는 10만원이며 청소년은 구매할 수 없습니다.</p>"
        "<p>경기 일정과 배당률 공지, 건전 구매 캠페인, 도박 문제 상담 전화 안내</p>",
    )


def n_security_news(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} - 피싱 수법 주의보",
        f"<h1>“환급금 준다” 문자 조심… {p['brand']} 피싱 주의보</h1>"
        "<p>최근 환급금을 미끼로 수수료 입금을 요구하거나 가짜 은행 사이트에서 OTP 번호와 보안카드 번호를 입력하게 하는 "
        "수법이 늘고 있다. 전문가들은 계좌 이체를 요구하는 문자는 무시하고 공식 앱으로만 확인하라고 조언했다.</p>"
        "<p>기자 이름 · 입력 시간 · 관련 기사</p>",
    )


def n_webmail_login(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 로그인",
        f"<h1>{p['brand']}</h1>"
        + _form([("메일 주소", "email", "email"), ("비밀번호", "password", "password")], "로그인")
        + "<p>비밀번호 찾기 · 회원가입 · 2단계 인증 설정 안내</p>",
    )


def n_investment_info(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 펀드 상품 안내",
        f"<h1>{p['brand']} 글로벌 배당 펀드</h1><p>최근 1년 수익률 {p['rate']}% (과거 수익률이 미래 수익을 보장하지 "
        "않습니다). 이 상품은 원금 손실이 발생할 수 있으며 예금자보호법에 따라 보호되지 않습니다.</p>"
        "<p>투자설명서 · 집합투자규약 · 판매 보수 안내</p>",
    )


def n_donation(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 정기 후원",
        f"<h1>{p['brand']} 함께 나눔</h1><p>아동 급식 지원을 위한 정기 후원을 받고 있습니다. 후원금은 연말정산 기부금 "
        "영수증이 발급됩니다.</p>"
        f"<p>후원 계좌: 가상은행 {p['account']} (예금주: 재단법인 {p['brand']}) · 연간 결산 보고서 공개</p>",
    )


def n_game_forum(p: dict) -> tuple[str, str]:
    return (
        f"{p['brand']} 커뮤니티",
        f"<h1>{p['brand']} 게임 커뮤니티</h1><p>이번 주 업데이트: 신규 던전, 캐시 충전 이벤트(게임 내 재화 10% 추가)</p>"
        "<p>공략 게시판 · 길드 모집 · 자유 게시판 · 운영 정책</p>",
    )


FAMILIES: list[Family] = [
    Family(
        "P-A",
        "phishing",
        "dev",
        ("static", "delayed", "redirect", "jsnav"),
        ("한결은행", "누리은행", "바다은행", "솔빛은행"),
        p_bank_security,
        "은행 보안 인증 사칭",
    ),
    Family(
        "P-B",
        "phishing",
        "eval",
        ("static", "delayed", "redirect", "jsnav"),
        ("새빛카드", "하나로카드", "별빛카드", "온누리카드"),
        p_card_payment,
        "카드 결제 오류 사칭",
    ),
    Family(
        "P-C",
        "phishing",
        "dev",
        ("static", "delayed", "redirect"),
        ("다온택배", "빠른택배", "한길로지스"),
        p_customs,
        "택배 통관 사칭",
    ),
    Family(
        "P-D",
        "phishing",
        "eval",
        ("static", "delayed", "redirect"),
        ("누리메일", "하늘메일", "바른메일"),
        p_webmail,
        "웹메일 계정 사칭",
    ),
    Family(
        "P-E",
        "phishing",
        "dev",
        ("static", "delayed", "redirect"),
        ("전자민원마당", "민원한눈에", "생활민원24"),
        p_gov_cert,
        "공공 민원 인증서 사칭",
    ),
    Family(
        "P-F",
        "phishing",
        "eval",
        ("static", "delayed", "redirect"),
        ("코인누리", "비트하늘", "체인온"),
        p_crypto_wallet,
        "가상자산 지갑 사칭",
    ),
    Family(
        "S-A",
        "scam",
        "dev",
        ("static", "delayed", "redirect", "jsnav"),
        ("정부환급지원센터", "환급조회서비스", "국민환급센터", "생활지원금센터"),
        s_tax_refund,
        "환급금 수수료 선입금",
    ),
    Family(
        "S-B",
        "scam",
        "eval",
        ("static", "delayed", "redirect", "jsnav"),
        ("황금열쇠", "주식명가", "수익나라", "코인리더스"),
        s_investment,
        "투자 리딩방",
    ),
    Family(
        "S-C",
        "scam",
        "dev",
        ("static", "delayed", "redirect"),
        ("하나로론", "바로대출", "서민금융지원"),
        s_loan_fee,
        "대출 보증료 선입금",
    ),
    Family(
        "S-D",
        "scam",
        "eval",
        ("static", "delayed", "redirect"),
        ("다온택배", "빠른택배", "한길로지스"),
        s_delivery_fee,
        "택배 재배송 수수료",
    ),
    Family(
        "S-E",
        "scam",
        "dev",
        ("static", "delayed", "redirect"),
        ("행복쇼핑", "럭키몰", "이벤트나라"),
        s_prize,
        "경품 당첨 제세공과금",
    ),
    Family(
        "S-F",
        "scam",
        "eval",
        ("static", "delayed", "redirect"),
        ("스마트잡", "재택왕", "부업천국"),
        s_job,
        "고수익 부업 보증금",
    ),
    Family(
        "G-A",
        "gambling",
        "dev",
        ("static", "delayed", "redirect", "jsnav"),
        ("WINNER BET", "GOAL 365", "빅매치", "스타벳"),
        g_toto,
        "사설 스포츠 토토",
    ),
    Family(
        "G-B",
        "gambling",
        "eval",
        ("static", "delayed", "redirect", "jsnav"),
        ("로얄카지노", "마카오라이브", "골드딜러", "에이스카지노"),
        g_casino,
        "라이브 카지노",
    ),
    Family(
        "G-C",
        "gambling",
        "dev",
        ("static", "delayed", "redirect"),
        ("슬롯킹", "잭팟월드", "럭키스핀"),
        g_slot,
        "온라인 슬롯",
    ),
    Family(
        "G-D",
        "gambling",
        "eval",
        ("static", "delayed", "redirect"),
        ("파워픽", "사다리왕", "미니게임천국"),
        g_minigame,
        "파워볼 미니게임",
    ),
    Family(
        "G-E",
        "gambling",
        "dev",
        ("static", "delayed", "redirect"),
        ("질주경마", "명마레이스", "스피드경륜"),
        g_horse,
        "사설 경마·경륜",
    ),
    Family(
        "G-F",
        "gambling",
        "eval",
        ("static", "delayed", "redirect"),
        ("안전놀이터", "보증사이트", "메이저놀이터"),
        g_invite,
        "놀이터 가입 안내",
    ),
    Family(
        "N-A",
        "normal",
        "dev",
        ("static", "delayed", "redirect"),
        ("바른은행", "가온은행", "도담은행"),
        n_bank_login,
        "정상 은행 로그인",
    ),
    Family(
        "N-B",
        "normal",
        "eval",
        ("static", "delayed", "redirect"),
        ("초록마켓", "하루쇼핑", "도토리몰"),
        n_checkout,
        "정상 쇼핑몰 결제",
    ),
    Family(
        "N-C",
        "normal",
        "dev",
        ("static", "delayed", "redirect"),
        ("가람시", "누리군", "한빛구"),
        n_refund_info,
        "지자체 환급 안내",
    ),
    Family(
        "N-D",
        "normal",
        "eval",
        ("static", "delayed", "redirect"),
        ("다온택배", "빠른택배", "한길로지스"),
        n_tracking,
        "정상 배송 조회",
    ),
    Family(
        "N-E",
        "normal",
        "dev",
        ("static", "delayed", "redirect"),
        ("스포츠 투표권 안내", "건전 구매 센터", "공식 발행사 안내"),
        n_legal_lottery,
        "합법 체육진흥투표권 안내",
    ),
    Family(
        "N-F",
        "normal",
        "eval",
        ("static", "delayed", "redirect"),
        ("하루뉴스", "바른일보", "누리신문"),
        n_security_news,
        "피싱 주의 기사",
    ),
    Family(
        "N-G",
        "normal",
        "dev",
        ("static", "delayed", "redirect"),
        ("누리메일", "하늘메일", "바른메일"),
        n_webmail_login,
        "정상 웹메일 로그인",
    ),
    Family(
        "N-H",
        "normal",
        "eval",
        ("static", "delayed", "redirect"),
        ("든든자산운용", "미래투자", "한결증권"),
        n_investment_info,
        "정상 펀드 안내",
    ),
    Family(
        "N-I",
        "normal",
        "dev",
        ("static", "delayed", "redirect"),
        ("나눔재단", "희망씨앗", "사랑의밥상"),
        n_donation,
        "정상 후원 안내",
    ),
    Family(
        "N-J",
        "normal",
        "eval",
        ("static", "delayed", "redirect"),
        ("모험의땅", "용사의길", "별빛온라인"),
        n_game_forum,
        "게임 커뮤니티",
    ),
]
