"""
collectors/_ip.py
-----------------
One definition of "worth sending to a third-party IP-reputation service".

Three collectors each carried their own `_is_private`. Two of them (GreyNoise,
AbuseIPDB) used string prefixes, which:

  * treated PUBLIC space as private: `startswith("172.2")` matches
    172.2.0.0/16 and 172.200.0.0/13-ish blocks, so those addresses were
    silently never enriched;
  * treated `startswith("fd")` as IPv6 unique-local, which also matches any
    string that merely begins with "fd";
  * passed malformed strings straight through to a rate-limited API, spending
    quota on a guaranteed miss;
  * missed CGNAT (100.64.0.0/10), multicast and documentation ranges.

`ipaddress.ip_address(...).is_global` answers most of the question properly.
It has one quirk worth knowing: IPv4 multicast (224.0.0.0/4) reports
is_global=True, so multicast and reserved space are excluded explicitly.
"""

from __future__ import annotations

import ipaddress


def is_public_ip(value: str) -> bool:
    """True only for a syntactically valid, globally routable address.

    Anything else (private, loopback, link-local, CGNAT, multicast,
    documentation/benchmark ranges, or not an IP at all) returns False,
    because no third-party service has useful data for it and a lookup would
    only spend quota.
    """
    try:
        addr = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast and not addr.is_reserved
