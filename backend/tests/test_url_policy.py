"""SC-IN-03 (SSRF) / SC-IN-06 (URL 정규화) 시험."""

import pytest

from app.security.url_policy import UrlPolicyError, normalize_candidate_url


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://Example.COM/login?a=1#frag", "https://example.com/login?a=1"),
        ("http://example.com", "http://example.com/"),
        ("https://example.com:443/x", "https://example.com/x"),
        ("https://example.com:8443/x", "https://example.com:8443/x"),
        ("https://한국.kr/", "https://xn--3e0b707e.kr/"),
        ("  https://example.com/  ", "https://example.com/"),
        ("https://bad.cafe/", "https://bad.cafe/"),
        ("http://8.8.8.8/", "http://8.8.8.8/"),
    ],
)
def test_accepts_and_normalizes(raw: str, expected: str) -> None:
    assert normalize_candidate_url(raw).normalized == expected


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("ftp://example.com/", "scheme_not_allowed"),
        ("javascript:alert(1)", "scheme_not_allowed"),
        ("file:///etc/passwd", "scheme_not_allowed"),
        ("https://user:pw@example.com/", "userinfo_not_allowed"),
        ("http://localhost/", "host_not_allowed"),
        ("http://api.localhost/", "host_not_allowed"),
        ("http://db.internal/", "host_not_allowed"),
        ("http://intranet/", "single_label_host"),
        ("http://127.0.0.1/", "ip_not_allowed"),
        ("http://10.0.0.5/", "ip_not_allowed"),
        ("http://192.168.0.1/", "ip_not_allowed"),
        ("http://169.254.169.254/latest/meta-data/", "ip_not_allowed"),
        ("http://[::1]/", "ip_not_allowed"),
        ("http://[::ffff:127.0.0.1]/", "ip_not_allowed"),
        ("http://0.0.0.0/", "ip_not_allowed"),
        ("http://2130706433/", "ambiguous_numeric_host"),
        ("http://0x7f.0.0.1/", "ambiguous_numeric_host"),
        ("http://0177.0.0.1/", "ambiguous_numeric_host"),
        ("https://example.com:22/", "port_not_allowed"),
        ("https://exa mple.com/", "invalid_chars"),
        ("https://example.com/\r\nX-Injected: 1", "invalid_chars"),
        ("https://", "missing_host"),
        ("https://example.com:99999/", "invalid_url"),
    ],
)
def test_rejects(raw: str, code: str) -> None:
    with pytest.raises(UrlPolicyError) as exc:
        normalize_candidate_url(raw)
    assert exc.value.code == code


def test_rejects_too_long() -> None:
    with pytest.raises(UrlPolicyError) as exc:
        normalize_candidate_url("https://example.com/" + "a" * 3000)
    assert exc.value.code == "invalid_length"


def test_allowlist_permits_dev_testsite() -> None:
    result = normalize_candidate_url("http://testsites:8080/phishing.html", host_allowlist={"testsites"})
    assert result.normalized == "http://testsites:8080/phishing.html"


def test_same_url_same_hash() -> None:
    a = normalize_candidate_url("https://EXAMPLE.com/a#x")
    b = normalize_candidate_url("https://example.com/a")
    assert a.sha256 == b.sha256
