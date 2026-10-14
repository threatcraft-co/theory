"""
theory.disk_cache
-----------------
One TTL cache for every collector, replacing a `_load_cache`/`_save_cache`
pair that had been copied into a dozen modules (each with its own timestamp
format: ISO strings in most, epoch floats in Shodan).

What it guarantees
------------------
* Entries are JSON files named from a slug *plus a hash* of the key, so a
  hostile or odd key (`../../x`, an IPv6 address, 300 characters of unicode)
  can never leave the cache directory or collide with another key.
* Writes are atomic (temp file + replace). A crash mid-write cannot leave a
  half-written entry that parses as something else.
* A corrupt, truncated or old-format file is a miss, never an exception.
* The cache is best-effort: if the disk is read-only or full, collectors
  carry on uncached rather than crashing the run.
* The directory is resolved on use, not at import, so THEORY_HOME and the
  test suite's hermetic CWD are honoured.

Misses vs failures
------------------
`fetch()` is where the HttpClient contract is enforced:

    loader raises NotFound  -> remembered as a miss, `default` returned
    loader raises anything else -> propagates; **nothing is cached**

The previous per-collector code cached an empty result on any exception,
which meant one timeout (or one 429) read as "no data" for 24 hours to a
week. See HttpError.is_definitive_miss.

Old cache files (no "v" field) are ignored and overwritten, so the first run
after upgrading refetches once.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable

from theory import paths
from theory._net import atomic_write
from theory.http_client import HttpError

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
_SLUG_RE = re.compile(r"[^a-z0-9_.-]+")
_MAX_SLUG = 60


@dataclass(frozen=True)
class CacheEntry:
    value: Any
    is_miss: bool
    age_seconds: float


class DiskCache:
    """A TTL cache for one source's responses.

    `namespace` is the per-source directory under the cache root. `ttl`
    applies to real answers; `miss_ttl` (default: same as `ttl`) applies to
    remembered "the source has nothing" results.
    """

    def __init__(
        self,
        namespace: str,
        *,
        ttl: timedelta,
        miss_ttl: timedelta | None = None,
        root: Path | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.namespace = namespace
        self.ttl = ttl
        self.miss_ttl = miss_ttl if miss_ttl is not None else ttl
        self._root = root
        self._clock = clock

    # -- location -----------------------------------------------------------

    @property
    def directory(self) -> Path:
        """Resolved on every use so env overrides and chdir are respected."""
        return self._root if self._root is not None else paths.cache_path(self.namespace)

    def _file_for(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
        slug = _SLUG_RE.sub("_", key.lower()).strip("._")[:_MAX_SLUG] or "key"
        return self.directory / f"{slug}-{digest}.json"

    # -- read / write -------------------------------------------------------

    def get(self, key: str) -> CacheEntry | None:
        """Return a live entry, or None if absent, expired, or unreadable."""
        path = self._file_for(key)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(payload, dict) or payload.get("v") != SCHEMA_VERSION:
            return None
        stored_at = payload.get("stored_at")
        if not isinstance(stored_at, (int, float)) or isinstance(stored_at, bool):
            return None
        is_miss = bool(payload.get("miss"))
        age = self._clock() - stored_at
        limit = (self.miss_ttl if is_miss else self.ttl).total_seconds()
        if age < 0 or age > limit:
            return None
        return CacheEntry(value=payload.get("value"), is_miss=is_miss, age_seconds=age)

    def put(self, key: str, value: Any) -> None:
        self._write(key, value, miss=False)

    def put_miss(self, key: str) -> None:
        self._write(key, None, miss=True)

    def _write(self, key: str, value: Any, *, miss: bool) -> None:
        record = {
            "v": SCHEMA_VERSION,
            "stored_at": self._clock(),
            "miss": miss,
            "value": value,
        }
        try:
            data = json.dumps(record).encode("utf-8")
            atomic_write(self._file_for(key), data)
        except (OSError, TypeError, ValueError) as exc:
            logger.warning("cache write skipped for %s: %s", self.namespace, exc)

    # -- the pattern every collector repeated -------------------------------

    def fetch(
        self,
        key: str,
        loader: Callable[[], Any],
        *,
        default: Any = None,
    ) -> Any:
        """Return the cached value, or call `loader` and remember its result.

        * Fresh hit        -> returned without calling `loader`.
        * Remembered miss  -> `default` returned without calling `loader`.
        * `loader` raises a definitive miss (NotFound) -> remembered, `default`.
        * `loader` raises anything else -> re-raised, nothing cached.
        """
        entry = self.get(key)
        if entry is not None:
            return default if entry.is_miss else entry.value
        try:
            value = loader()
        except HttpError as exc:
            if exc.is_definitive_miss:
                self.put_miss(key)
                return default
            raise
        self.put(key, value)
        return value
