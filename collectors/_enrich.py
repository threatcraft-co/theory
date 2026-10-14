"""
collectors/_enrich.py
---------------------
The per-indicator lookup loop shared by the enrichment collectors
(AbuseIPDB, GreyNoise, Shodan InternetDB, urlscan.io).

Each of them used to carry its own copy of this loop, and the copies agreed
on one thing: *any* lookup that did not produce data was cached as "this
indicator is clean / unknown", for 1 to 7 days. That conflated three very
different outcomes:

    the source answered "nothing on file"   -> a real answer, cache it
    the source refused us (429)             -> we learned nothing
    the network or the source broke         -> we learned nothing

GreyNoise's community tier allows ~50 lookups a week. The old code logged
"rate limited ... stopping enrichment", did not stop, and then cached every
remaining IP as `classification: unknown` for seven days.

Rules enforced here, in one place:

    cache hit                  free: no request, no pacing; still served
                               after the run has stopped
    loader returns a dict      cached, included in results
    loader returns None        the source has nothing: cached as a miss and
                               left OUT of results (same on first run and
                               every run after; the old cached-sentinel dicts
                               made a second run annotate IPs the first run
                               had not)
    NotFound                   same as None
    RateLimited                stop making requests; nothing cached for the
                               remaining keys (cache hits are still served)
    any other HttpError        not cached, move on; after
                               `max_consecutive_failures` in a row, stop
                               (an offline laptop should fail in seconds, not
                               grind through 40 lookups with retries each)

A run that did not finish says so in exactly one warning.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from theory.disk_cache import DiskCache
from theory.http_client import HttpError, NotFound, RateLimited

logger = logging.getLogger(__name__)

DEFAULT_MAX_CONSECUTIVE_FAILURES = 3


@dataclass
class EnrichStats:
    cached: int = 0          # served from cache without a request
    live: int = 0            # answered by the source (data or definitive miss)
    failed: int = 0          # request failed; not cached
    not_attempted: int = 0   # skipped because the run stopped early
    stopped: str | None = None
    first_error: str | None = None
    failed_keys: list[str] = field(default_factory=list)


def enrich_keys(
    keys: Iterable[str],
    *,
    cache: DiskCache,
    load: Callable[[str], dict[str, Any] | None],
    source: str,
    pace: float = 0.3,
    max_consecutive_failures: int = DEFAULT_MAX_CONSECUTIVE_FAILURES,
) -> tuple[dict[str, dict[str, Any]], EnrichStats]:
    """Look up each key, honouring the cache and the rules above.

    `load(key)` returns a context dict, or None if the source has nothing for
    that key. It raises HttpError for anything that is not an answer.

    Returns (results, stats). `results` contains only real data.
    """
    key_list = list(keys)
    results: dict[str, dict[str, Any]] = {}
    stats = EnrichStats()
    consecutive = 0
    halted = False        # once set, no more requests; cache is still served

    for key in key_list:
        entry = cache.get(key)
        if entry is not None:
            stats.cached += 1
            if not entry.is_miss and entry.value:
                results[key] = entry.value
            continue

        if halted:
            stats.not_attempted += 1
            continue

        try:
            value = load(key)
        except NotFound:
            cache.put_miss(key)
            stats.live += 1
            consecutive = 0
            time.sleep(pace)
            continue
        except RateLimited as exc:
            halted = True
            stats.stopped = "rate limited"
            stats.first_error = stats.first_error or str(exc)
            stats.not_attempted += 1
            continue
        except HttpError as exc:
            stats.failed += 1
            stats.failed_keys.append(key)
            stats.first_error = stats.first_error or str(exc)
            consecutive += 1
            if consecutive >= max_consecutive_failures:
                halted = True
                stats.stopped = f"{consecutive} consecutive failures"
            continue

        consecutive = 0
        stats.live += 1
        if value:
            cache.put(key, value)
            results[key] = value
        else:
            cache.put_miss(key)
        time.sleep(pace)

    _report(source, stats, total=len(key_list))
    return results, stats


def _report(source: str, stats: EnrichStats, *, total: int) -> None:
    if stats.stopped:
        logger.warning(
            "%s: stopped early (%s) after %d of %d lookups; %d not attempted, "
            "%d failed. Failures are not cached; the next run will retry. "
            "First error: %s",
            source, stats.stopped, stats.live + stats.cached, total,
            stats.not_attempted, stats.failed, stats.first_error,
        )
    elif stats.failed:
        logger.warning(
            "%s: %d of %d lookups failed and were not cached; the next run will "
            "retry them. First error: %s",
            source, stats.failed, total, stats.first_error,
        )
