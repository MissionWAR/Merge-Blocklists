#!/usr/bin/env python3
"""
cache_utils.py

Utility functions and classes for lightweight caching of fetched filterlists.

Responsibilities:
 - Provide atomic writes for cached text files.
 - Generate filesystem-safe filenames for URLs.
 - Maintain metadata (ETag, Last-Modified, SHA256, etc.) for optional conditional fetches.
 - Serve as a fallback layer if remote downloads fail or are unchanged.

This module does not perform any network fetching logic.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import time
from pathlib import Path
from typing import Any


CACHE_META_FILENAME = "meta.json"


# ----------------------------------------
# Helpers
# ----------------------------------------
def sanitize_filename(url: str, max_len: int = 180) -> str:
    """
    Return a filesystem-safe filename derived from `url`.

    Ensures deterministic and unique names by appending
    the first 16 characters of the SHA256 digest.
    """
    name = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    suffix = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    max_body = max_len - (len(suffix) + 1)
    if len(name) > max_body:
        name = name[:max_body]
    return f"{name}_{suffix}.txt"


def atomic_write_text(target: Path, text: str, encoding: str = "utf-8") -> None:
    """
    Atomically write `text` to `target`.

    Ensures the target directory exists and performs an atomic
    replacement of the file to avoid corruption on interruption.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", delete=False, dir=target.parent, encoding=encoding
    ) as tmp:
        tmp.write(text)
        tmp_path = Path(tmp.name)
    try:
        tmp_path.replace(target)
    except Exception:
        # Only unlink if replace failed (file still exists)
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise


# ----------------------------------------
# Cache Manager
# ----------------------------------------
class CacheManager:
    """Manage cached files and metadata for fetched lists."""

    def __init__(self, cache_dir: str | Path) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.meta_path = self.cache_dir / CACHE_META_FILENAME
        self._meta: dict[str, dict[str, Any]] = {}
        self._load()

    # --------------------
    # Metadata I/O
    # --------------------
    def _load(self) -> None:
        """Load metadata file if available. Silently creates empty metadata on corruption."""
        if not self.meta_path.exists():
            return
        try:
            content = self.meta_path.read_text(encoding="utf-8")
            self._meta = json.loads(content)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            # Corrupted metadata - start fresh
            import sys
            print(f"Warning: Cache metadata corrupted ({type(e).__name__}), starting fresh", file=sys.stderr)
            self._meta = {}

    def save(self) -> None:
        """Persist metadata safely to disk."""
        try:
            atomic_write_text(
                self.meta_path,
                json.dumps(self._meta, indent=2, sort_keys=True, ensure_ascii=False)
                + "\n",
            )
        except Exception as e:
            # best-effort; cache persistence should not fail the pipeline
            # but log for debugging
            import sys
            print(f"Warning: Failed to save cache metadata: {e}", file=sys.stderr)

    # --------------------
    # Public API
    # --------------------
    def get_meta(self, url: str) -> dict[str, Any] | None:
        """Return stored metadata for a given URL, if any."""
        return self._meta.get(url)

    def path_for_url(self, url: str) -> Path:
        """Compute the expected cache file path for a given URL."""
        return self.cache_dir / sanitize_filename(url)

    def record_fetch(
        self,
        url: str,
        cache_file: Path,
        etag: str | None,
        last_modified: str | None,
        content_sha256: str | None,
        status_code: int,
    ) -> None:
        """Record a completed fetch operation to metadata."""
        now = int(time.time())
        meta = {
            "url": url,
            "path": str(cache_file),
            "etag": etag,
            "last_modified": last_modified,
            "content_sha256": content_sha256,
            "status_code": status_code,
        }
        self._meta[url] = meta
        self.save()

    def get_cached_file(self, url: str) -> Path | None:
        """
        Return Path to cached file if it exists, or None.

        Falls back to computed path_for_url() if recorded path is missing.
        """
        meta = self._meta.get(url)
        if not meta:
            p = self.path_for_url(url)
            return p if p.exists() else None

        recorded_path = meta.get("path", "")
        if recorded_path:
            recorded = Path(recorded_path)
            if recorded.exists():
                return recorded

        fallback = self.path_for_url(url)
        return fallback if fallback.exists() else None
