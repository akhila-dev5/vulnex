"""Small cached JSON HTTP helper shared by every vulnerability source.

Every response is cached on disk keyed by source + logical key, which keeps
repeated scans reproducible and cheap, and makes the scanner resilient to
transient upstream failures (a cached response is reused when a request fails).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import requests

from . import config

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_key(key: str) -> str:
    key = _SAFE.sub("_", key)
    if len(key) > 120:
        digest = hashlib.sha1(key.encode()).hexdigest()[:12]
        key = key[:100] + "_" + digest
    return key


class CachedHTTP:
    """A requests session with per-source on-disk JSON caching."""

    def __init__(self, name: str, session: requests.Session | None = None):
        self.name = name
        self.cache_dir = config.CACHE_DIR / "http" / name
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", config.user_agent())

    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / f"{_safe_key(key)}.json"

    def get_json(
        self,
        url: str,
        key: str,
        params: dict | None = None,
        headers: dict | None = None,
        force: bool = False,
        timeout: int | None = None,
    ):
        """GET a JSON document, using the cache when available."""
        cache = self._cache_path(key)
        if cache.exists() and not force:
            try:
                return json.loads(cache.read_text())
            except json.JSONDecodeError:
                pass
        try:
            resp = self.session.get(
                url, params=params, headers=headers, timeout=timeout or config.HTTP_TIMEOUT
            )
        except requests.RequestException:
            return None
        if resp.status_code == 404:
            # Cache negative results so we do not re-query known-missing items.
            cache.write_text("null")
            return None
        if resp.status_code >= 400:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        cache.write_text(json.dumps(data))
        return data

    def post_json(
        self,
        url: str,
        body: dict,
        key: str,
        headers: dict | None = None,
        force: bool = False,
        timeout: int | None = None,
    ):
        cache = self._cache_path(key)
        if cache.exists() and not force:
            try:
                return json.loads(cache.read_text())
            except json.JSONDecodeError:
                pass
        try:
            resp = self.session.post(
                url,
                data=json.dumps(body),
                headers={"Content-Type": "application/json", **(headers or {})},
                timeout=timeout or config.HTTP_TIMEOUT,
            )
        except requests.RequestException:
            return None
        if resp.status_code >= 400:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        cache.write_text(json.dumps(data))
        return data
