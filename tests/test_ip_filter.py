"""
tests/test_ip_filter.py
-----------------------
collectors/_ip.is_public_ip: the one filter GreyNoise, AbuseIPDB and Shodan
InternetDB use to decide which IPs are worth a lookup.

Replaces three copies of `_is_private`. Two of them used string prefixes and
got public address space wrong in both directions.
"""

from __future__ import annotations

import pytest

from collectors._ip import is_public_ip


@pytest.mark.parametrize("ip", [
    "8.8.8.8", "185.220.101.1", "1.1.1.1", "203.0.113.1".replace("203.0.113.1", "93.184.216.34"),
    "2001:4860:4860::8888",
])
def test_public_addresses_are_looked_up(ip):
    assert is_public_ip(ip)


@pytest.mark.parametrize("ip", [
    # The bug: public space the old prefix match skipped
    "172.2.3.4", "172.200.1.1", "172.64.0.1", "172.217.0.1", "172.32.0.1", "172.15.255.255",
])
def test_public_172_space_is_not_mistaken_for_rfc1918(ip):
    """Regression: startswith("172.2") matched 172.2.0.0/16 and everything in
    172.200.0.0-172.255.255.255, none of which is private."""
    assert is_public_ip(ip)


@pytest.mark.parametrize("ip", [
    "10.0.0.1", "10.255.255.255",
    "172.16.0.1", "172.20.1.1", "172.31.255.255",
    "192.168.1.1",
    "127.0.0.1", "127.1.2.3",
    "169.254.1.1",
    "0.0.0.0",
    "::1", "fe80::1", "fd00::1", "fc00::1",
])
def test_private_loopback_and_link_local_are_skipped(ip):
    assert not is_public_ip(ip)


@pytest.mark.parametrize("ip", [
    "100.64.0.1",        # CGNAT: shared address space, never globally routable
    "224.0.0.1",         # multicast
    "255.255.255.255",   # broadcast
    "198.18.0.1",        # benchmarking
    "192.0.2.1",         # documentation (TEST-NET-1)
    "2001:db8::1",       # documentation (IPv6)
])
def test_other_non_global_ranges_are_skipped(ip):
    """The old prefix lists missed all of these."""
    assert not is_public_ip(ip)


@pytest.mark.parametrize("value", [
    "", "   ", "not-an-ip", "fdic.example.com", "fd", "1.2.3", "1.2.3.4.5",
    "999.1.1.1", "8.8.8.8:443", "8.8.8.8/24", "evil.com", None,
])
def test_malformed_input_is_skipped_and_never_spends_quota(value):
    """Regression: "fdic.example.com" matched startswith("fd") and counted as
    private by accident; "not-an-ip" was *sent to the API* by the old filter."""
    assert not is_public_ip(value)


def test_surrounding_whitespace_is_tolerated():
    assert is_public_ip("  8.8.8.8\n")
