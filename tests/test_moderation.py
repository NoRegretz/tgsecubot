import pytest

from security_bot.moderation import (
    contains_blocked_url,
    contains_evm_address,
    extract_urls,
    host_allowed,
    name_matches_keywords,
    normalize_domain,
)


def test_normalize_domain_accepts_plain_domain_and_urls():
    assert normalize_domain("x.com") == "x.com"
    assert normalize_domain("https://www.x.com/path") == "x.com"


def test_normalize_domain_rejects_invalid_values():
    with pytest.raises(ValueError):
        normalize_domain("not-a-domain")


def test_host_allowed_matches_domain_and_subdomains():
    assert host_allowed("x.com", ["x.com"])
    assert host_allowed("mobile.x.com", ["x.com"])
    assert not host_allowed("evilx.com", ["x.com"])


def test_extract_urls_finds_domains_and_schemed_urls():
    urls = extract_urls("see https://example.com/a and www.x.com and test.org.")
    assert [url.host for url in urls] == ["example.com", "x.com", "test.org"]


def test_contains_blocked_url_ignores_allowed_domains():
    assert not contains_blocked_url("go to https://x.com/profile", ["x.com"])
    assert contains_blocked_url("go to https://example.com", ["x.com"])


def test_decimal_numbers_are_not_detected_as_urls():
    assert extract_urls("profit is 1.5% and volume is 22.3K") == []
    assert not contains_blocked_url("profit is 1.5% and volume is 22.3K", [])


def test_contains_evm_address_detects_address_like_text():
    assert contains_evm_address("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
    assert contains_evm_address("User0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
    assert contains_evm_address("User 0x742d35Cc6634C0532925a3b844Bc454e4438f44e Name")
    assert not contains_evm_address("0x1234")


@pytest.mark.parametrize("prefix", ["0x", "0X", "Ox", "OX", "ox", "oX"])
def test_evm_detector_includes_letter_o_prefix_lookalikes(prefix):
    address = prefix + "ffDA10b7fd9Cf172e0502A6Bc0e5E355516c5232"
    assert contains_evm_address(address)
    assert contains_evm_address(f"Support {address} team")
    assert contains_evm_address(f"User{address}")


@pytest.mark.parametrize("text", ["O instead of 0", "Ox", "oxygen", "ox1234", "Ox" + "a" * 39, "Ox" + "g" * 40])
def test_evm_lookalike_detection_does_not_match_ordinary_or_short_text(text):
    assert not contains_evm_address(text)


def test_name_matches_keywords_case_insensitive():
    assert name_matches_keywords("Meta Support", ["meta"])
    assert not name_matches_keywords("Regular User", ["meta"])
