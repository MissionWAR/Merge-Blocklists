#!/usr/bin/env python3
"""
cache_utils.py

Utility functions and classes for lightweight caching of fetched filterlists.

Responsibilities:
 - Provide atomic writes for cached text files.
 - Generate filesystem-safe filenames for URLs.
 - Maintain metadata (ETag, Last-Modified, SHA256, etc.) for optional conditional fetches.
 - Serve as a fallback layer if remote downloads fail or are unchanged.
 - Provide reusable intermediate caches for expensive processing stages.

This module does not perform any network fetching logic.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from scripts import utils


CACHE_META_FILENAME = "meta.json"
INTERMEDIATE_META_FILENAME = "intermediate_meta.json"

IO_BUFFER_SIZE = utils.IO_BUFFER_SIZE


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
            print(
                f"Warning: Cache metadata corrupted ({type(e).__name__}), starting fresh",
                file=sys.stderr,
            )
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
            # best-effort; cache persistence should not fail the pipeline but log for debugging
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
        *,
        autosave: bool = True,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """
        Record a completed fetch operation to metadata.

        Set autosave=False to batch multiple updates before calling save() once.
        """
        now = int(time.time())
        meta = {
            "url": url,
            "path": str(cache_file),
            "etag": etag,
            "last_modified": last_modified,
            "content_sha256": content_sha256,
            "status_code": status_code,
            "fetched_at": now,
        }
        if extra:
            self._apply_meta_updates(meta, extra)
        self._meta[url] = meta
        if autosave:
            self.save()

    def update_meta(
        self, url: str, updates: dict[str, Any], *, autosave: bool = True
    ) -> None:
        """Merge `updates` into cached metadata for `url`."""
        if not updates:
            return
        meta = self._meta.get(url)
        if not meta:
            meta = {
                "url": url,
                "path": str(self.path_for_url(url)),
            }
            self._meta[url] = meta
        self._apply_meta_updates(meta, updates)
        if autosave:
            self.save()

    def _apply_meta_updates(self, target: dict[str, Any], updates: dict[str, Any]) -> None:
        """Apply metadata updates, removing keys when value is None."""
        for key, value in updates.items():
            if value is None:
                target.pop(key, None)
            else:
                target[key] = value

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


# ----------------------------------------
# Intermediate pipeline cache helpers
# ----------------------------------------
def hash_file(path: str | Path) -> str:
    """Return SHA256 hash of the given file."""
    digest = hashlib.sha256()
    path_obj = Path(path)
    with path_obj.open("rb") as fh:
        while True:
            chunk = fh.read(IO_BUFFER_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _copy_file_with_hash(
    src: Path, dest: Path, *, expected_hash: str | None = None
) -> str:
    """Copy src → dest atomically while computing (and optionally verifying) SHA256."""
    src_path = Path(src)
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb", delete=False, dir=dest_path.parent, prefix=".tmp_cache_copy_"
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            with src_path.open("rb") as src_file:
                while True:
                    chunk = src_file.read(IO_BUFFER_SIZE)
                    if not chunk:
                        break
                    digest.update(chunk)
                    tmp_file.write(chunk)
            tmp_file.flush()
        actual_hash = digest.hexdigest()
        if expected_hash and actual_hash != expected_hash:
            raise ValueError("cached file hash mismatch")
        tmp_path.replace(dest_path)
        tmp_path = None
        return actual_hash
    finally:
        if tmp_path and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def _normalize_rel_key(rel_path: str | Path) -> str:
    """Return POSIX-style relative path string for metadata keys."""
    return Path(rel_path).as_posix()


class IntermediateResultCache:
    """Cache cleaned+validated outputs keyed by relative filename and raw hash."""

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.meta_path = self.base_dir / INTERMEDIATE_META_FILENAME
        self.cleaned_dir = self.base_dir / "cleaned"
        self.validated_dir = self.base_dir / "validated"
        self.cleaned_dir.mkdir(parents=True, exist_ok=True)
        self.validated_dir.mkdir(parents=True, exist_ok=True)
        self._meta: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self.meta_path.exists():
            return
        try:
            content = self.meta_path.read_text(encoding="utf-8")
            self._meta = json.loads(content)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            print(
                f"Warning: Intermediate cache metadata corrupted ({type(exc).__name__}), resetting",
                file=sys.stderr,
            )
            self._meta = {}

    def save(self) -> None:
        try:
            atomic_write_text(
                self.meta_path,
                json.dumps(self._meta, indent=2, sort_keys=True, ensure_ascii=False)
                + "\n",
            )
        except Exception as exc:
            print(f"Warning: Failed to persist intermediate cache metadata: {exc}", file=sys.stderr)

    def _entry(self, key: str) -> dict[str, Any] | None:
        return self._meta.get(key)

    def invalidate(self, key: str | Path) -> None:
        """Remove metadata + cached files for key (best-effort)."""
        norm_key = _normalize_rel_key(key)
        self._meta.pop(norm_key, None)
        for base in (self.cleaned_dir, self.validated_dir):
            try:
                target = base / Path(norm_key)
                target.unlink(missing_ok=True)
            except OSError:
                pass

    def can_reuse(self, key: str | Path, raw_hash: str) -> bool:
        norm_key = _normalize_rel_key(key)
        entry = self._entry(norm_key)
        if not entry:
            return False
        return entry.get("raw_sha256") == raw_hash

    def restore(
        self, key: str | Path, cleaned_dest: Path, validated_dest: Path
    ) -> bool:
        """Copy cached cleaned/validated files into the provided destinations."""
        norm_key = _normalize_rel_key(key)
        entry = self._entry(norm_key)
        if not entry:
            return False
        cleaned_src = self.cleaned_dir / Path(norm_key)
        validated_src = self.validated_dir / Path(norm_key)
        cleaned_dest_path = Path(cleaned_dest)
        validated_dest_path = Path(validated_dest)
        if not cleaned_src.exists() or not validated_src.exists():
            self.invalidate(norm_key)
            return False
        try:
            _copy_file_with_hash(
                cleaned_src,
                cleaned_dest_path,
                expected_hash=entry.get("cleaned_sha256"),
            )
            _copy_file_with_hash(
                validated_src,
                validated_dest_path,
                expected_hash=entry.get("validated_sha256"),
            )
            return True
        except Exception:
            self.invalidate(norm_key)
            return False

    def store_result(
        self,
        key: str | Path,
        raw_hash: str,
        cleaned_src: Path,
        validated_src: Path,
    ) -> None:
        """Persist freshly generated cleaned/validated files with metadata."""
        norm_key = _normalize_rel_key(key)
        cleaned_src_path = Path(cleaned_src)
        validated_src_path = Path(validated_src)
        cleaned_cache_path = self.cleaned_dir / Path(norm_key)
        validated_cache_path = self.validated_dir / Path(norm_key)
        cleaned_hash = _copy_file_with_hash(cleaned_src_path, cleaned_cache_path)
        validated_hash = _copy_file_with_hash(validated_src_path, validated_cache_path)
        self._meta[norm_key] = {
            "raw_sha256": raw_hash,
            "cleaned_sha256": cleaned_hash,
            "validated_sha256": validated_hash,
            "cached_at": int(time.time()),
        }
        self.save()

    def raw_hash(self, path: str | Path) -> str:
        return hash_file(path)
