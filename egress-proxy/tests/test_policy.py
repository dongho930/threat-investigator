import pytest

from egress_proxy.policy import EgressPolicy


def resolver_for(mapping: dict[str, list[str]]):
    def resolve(host: str, port: int) -> list[str]:
        if host not in mapping:
            raise OSError("NXDOMAIN")
        return mapping[host]

    return resolve


POLICY = EgressPolicy(
    host_allowlist=frozenset({"testsites"}),
    resolver=resolver_for(
        {
            "public.example.com": ["93.184.216.34"],
            "v6.example.com": ["2606:2800:220:1::1"],
            "rebind.example.com": ["10.0.0.5"],
            "mixed.example.com": ["93.184.216.34", "127.0.0.1"],
            "mapped.example.com": ["::ffff:169.254.169.254"],
            "testsites": ["172.20.0.5"],
            "empty.example.com": [],
        }
    ),
)


def test_public_host_allowed_with_checked_ip() -> None:
    d = POLICY.decide("public.example.com", 443)
    assert d.allowed and d.ip == "93.184.216.34"


def test_ipv6_public_allowed() -> None:
    assert POLICY.decide("v6.example.com", 80).allowed


def test_allowlisted_dev_host_may_resolve_private() -> None:
    d = POLICY.decide("testsites", 8080)
    assert d.allowed and d.ip == "172.20.0.5"


@pytest.mark.parametrize(
    ("host", "port", "reason"),
    [
        ("public.example.com", 22, "port_not_allowed"),
        ("169.254.169.254", 80, "ip_not_allowed"),
        ("127.0.0.1", 8080, "ip_not_allowed"),
        ("[::1]", 443, "ip_not_allowed"),
        ("2130706433", 80, "ambiguous_numeric_host"),
        ("localhost", 80, "host_not_allowed"),
        ("db.internal", 80, "host_not_allowed"),
        ("backend", 8080, "host_not_allowed"),
        ("rebind.example.com", 80, "resolved_ip_not_allowed"),
        ("mixed.example.com", 80, "resolved_ip_not_allowed"),
        ("mapped.example.com", 80, "resolved_ip_not_allowed"),
        ("nxdomain.example.com", 80, "dns_failed"),
        ("empty.example.com", 80, "dns_failed"),
        ("bad host\r\nX: y", 80, "invalid_host"),
        ("", 80, "invalid_host"),
    ],
)
def test_blocked(host: str, port: int, reason: str) -> None:
    d = POLICY.decide(host, port)
    assert not d.allowed and d.reason == reason and d.ip is None
