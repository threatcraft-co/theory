"""
collectors/_abusech.py
----------------------
Shared handling for abuse.ch API replies (ThreatFox, URLhaus, MalwareBazaar).

abuse.ch reports failures *inside a 200 response* via `query_status`: a bad
or revoked Auth-Key, a rejected tag, a rate limit. The collectors used to
treat anything that was not literally "no_results" as "parse whatever list is
in there", so an error reply fell through to an empty list and was cached as
"this family has no IOCs" for a day.

`interpret_query_status` makes that an allowlist. Only a status that means
the source answered is returned to the caller; anything else raises
BadResponse, which DiskCache.fetch() never caches.
"""

from __future__ import annotations

from typing import Any

from theory.http_client import BadResponse

OK_STATUSES = frozenset({"ok"})

# The source answered and has nothing for this input. Safe to remember.
EMPTY_STATUSES = frozenset({"no_results"})


def interpret_query_status(
    data: Any,
    *,
    source: str,
    url: str,
    extra_empty: frozenset[str] = frozenset(),
) -> bool:
    """Decide what an abuse.ch reply means.

    Returns True if the payload carries results to parse, False if the source
    definitively has nothing. Raises BadResponse for anything else (wrong
    shape, unknown status, auth or rate-limit errors reported as HTTP 200).

    Only the status token is ever placed in the error message. It is a short
    enum from the API, never a credential.
    """
    if not isinstance(data, dict):
        raise BadResponse(f"{source}: unexpected response shape", url=url, status=200)

    status = str(data.get("query_status") or "").strip().lower()
    if status in OK_STATUSES:
        return True
    if status in EMPTY_STATUSES or status in extra_empty:
        return False
    raise BadResponse(
        f"{source}: query_status={status[:40] or 'missing'!r}", url=url, status=200,
    )
