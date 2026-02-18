from src.utils import validate_domain, validate_ip, validate_subdomain


def test_validate_ip_v4():
    assert validate_ip("1.2.3.4") is True
    assert validate_ip("255.255.255.255") is True
    assert validate_ip("0.0.0.0") is True


def test_validate_ip_v6():
    assert validate_ip("2001:db8::1") is True
    assert validate_ip("::1") is True


def test_validate_ip_invalid():
    assert validate_ip("1.2.3") is False
    assert validate_ip("1.2.3.4.5") is False
    assert validate_ip("256.256.256.256") is False
    assert validate_ip("hello") is False
    assert validate_ip("") is False


def test_validate_domain():
    assert validate_domain("example.com") is True
    assert validate_domain("sub.example.co.uk") is True
    assert validate_domain("a-b.com") is True


def test_validate_domain_invalid():
    assert validate_domain("example") is False
    assert validate_domain("-example.com") is False
    assert validate_domain("example.c") is False


def test_validate_subdomain():
    assert validate_subdomain("www") is True
    assert validate_subdomain("api-v1") is True
    assert validate_subdomain("@") is True
    assert validate_subdomain("") is True


def test_validate_subdomain_invalid():
    assert validate_subdomain("www.google") is False
    assert validate_subdomain("-abc") is False
    assert validate_subdomain("abc-") is False
