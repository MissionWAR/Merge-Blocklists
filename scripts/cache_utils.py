#!/usr/bin/env python3
"""
scripts/cache_utils.py

Improved, well-documented cache utilities for the fetcher.

Features & rationale
- Stable filenames: <sha1>.dat for content, <sha1>.meta.json for metadata.
- Backwards-compatibility when reading metadata: tries legacy filenames (.meta, .etag).
- Conditional GET using ETag and Last-Modified; if metadata is missing but .dat exists
  we fall back to using the file mtime as If-Modified-Since (heuristic to avoid re-downloads).
- Conservative urllib3 retry policy via session_with_retries().
- On transient/network errors we prefer to return an existing cached file if present.
- Atomic writes for both content and metadata.
- Small utility functions: get cache paths, read/write meta, compute cache size,
  and a helper to prune old/orphaned cache files.
- Minimal external dependencies: only `requests` is required.
- Includes a tiny CLI to inspect/prune the cache (safe, opt-in).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timedelta
from email.utils import formatdate
from pathlib import Path
from typing import Dict, Tuple, Optional

import requests

# -----------------------
# Logging
# -----------------------
logger = logging.getLogger("cache_utils")
if not logger.handlers:
    # default handler for local runs / CI logs
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)


def set_log_level(verbose: bool = False) -> None:
    """
    Convenience to switch to debug-level logs when you need more details.
    Call set_log_level(True) from scripts/CI or locally when debugging.
    """
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)


# -----------------------
# Constants & small helpers
# -----------------------
USER_AGENT = "filterlists-fetcher/1.0"
CHUNK_SIZE = 8192  # bytes when streaming downloads

# - metadata candidate filenames (backward compatibility)
_LEGACY_META_SUFFIXES = [".meta.json", ".meta", ".etag"]


def _key(url: str) -> str:
    """
    Deterministic filename key for a URL. Stable across runs.
    Exposed because other scripts (fetcher) may rely on it.
    """
    return hashlib.sha1(url.encode("utf-8")).hexdigest()


def get_cache_paths(cache_dir: str, key: str) -> Tuple[Path, Path, Path]:
    """
    Return (content_path, meta_json_path, cache_dir_path).
    content_path: <key>.dat
    meta_json_path: <key>.meta.json
    """
    cd = Path(cache_dir)
    return cd / f"{key}.dat", cd / f"{key}.meta.json", cd


# -----------------------
# Metadata I/O (robust)
# -----------------------
def _read_meta_any(meta_json: Path) -> Dict:
    """
    Try to read metadata from the main JSON file, falling back to legacy names.
    Returns a dict (empty if not found / unreadable).
    This helps when older runs produced different filenames for meta.
    """
    candidates = [meta_json] + [meta_json.with_suffix(s) for s in (".meta", ".etag")]
    for p in candidates:
        if not p.exists():
            continue
        try:
            txt = p.read_text(encoding="utf-8")
            try:
                return json.loads(txt)
            except Exception:
                # Attempt a simple "key: value" parse for legacy formats
                d: Dict[str, str] = {}
                for ln in txt.splitlines():
                    if ":" in ln:
                        k, v = ln.split(":", 1)
                        d[k.strip()] = v.strip()
                return d
        except Exception:
            continue
    return {}


def _write_meta(meta_json: Path, meta: Dict) -> None:
    """
    Atomically write JSON metadata to <key>.meta.json.
    We write a tmp file then replace to avoid partial writes on interruption.
    """
    tmp = meta_json.with_suffix(".meta.json.tmp")
    tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(meta_json)


# -----------------------
# Session with retries
# -----------------------
def session_with_retries(
    total: int = 2,
    backoff_factor: float = 0.2,
    status_forcelist: Tuple[int, ...] = (429, 500, 502, 503, 504),
) -> requests.Session:
    """
    Return a requests.Session configured with conservative urllib3 Retry policy.

    Defaults chosen to be quick-fail and to avoid long delays in CI:
      - total=2 (small number of retries)
      - backoff_factor=0.2 (short wait between retries)
    """
    from requests.adapters import HTTPAdapter

    try:
        from urllib3.util.retry import Retry  # type: ignore
    except Exception:
        # fallback to requests's vendored urllib3 if necessary
        from requests.packages.urllib3.util.retry import Retry  # type: ignore

    sess = requests.Session()
    retries = Retry(
        total=total,
        connect=total,
        read=total,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        raise_on_status=False,
        allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]),
    )
    adapter = HTTPAdapter(max_retries=retries)
    sess.mount("https://", adapter)
    sess.mount("http://", adapter)
    sess.headers.update({"User-Agent": USER_AGENT})
    return sess


# -----------------------
# Main: download with cache
# -----------------------
def download_with_cache(
    session: requests.Session, url: str, cache_dir: str, timeout: int = 60
) -> Tuple[bool, str]:
    """
    Download `url` into `cache_dir` using conditional requests.

    Returns:
      (True, path_to_dat) on success (path points to cached or freshly downloaded .dat)
      (False, error_message) on failure (no usable cached file)

    Behavior:
    - Uses ETag and Last-Modified from stored metadata when available.
    - If metadata missing but .dat exists, uses file's mtime to set If-Modified-Since
      (many servers support Last-Modified and will return 304).
    - On 304 -> return cached file.
    - On 2xx -> stream to a temp file and atomically replace .dat, then write meta.
    - On network/stream errors -> if .dat exists, return the cached file (best-effort).
    """
    os.makedirs(cache_dir, exist_ok=True)
    key = _key(url)
    content_path, meta_json, cd = get_cache_paths(cache_dir, key)

    # read metadata (including legacy names)
    meta = _read_meta_any(meta_json)
    headers: Dict[str, str] = {}
    if meta.get("etag"):
        headers["If-None-Match"] = meta["etag"]
    if meta.get("last_modified"):
        headers["If-Modified-Since"] = meta["last_modified"]

    # If no last-modified present but .dat exists, use mtime fallback (best-effort)
    if "If-Modified-Since" not in headers and content_path.exists():
        try:
            mtime = content_path.stat().st_mtime
            headers["If-Modified-Since"] = formatdate(timeval=mtime, usegmt=True)
            logger.debug("Using mtime fallback If-Modified-Since=%s for %s", headers["If-Modified-Since"], url)
        except Exception:
            logger.debug("Failed to read mtime for fallback for %s", url)

    # perform GET with streaming
    try:
        resp = session.get(url, headers=headers, stream=True, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        # network-level error: prefer cached file if it exists
        logger.warning("Network error while fetching %s: %s", url, exc)
        if content_path.exists():
            logger.info("Falling back to cached file for %s -> %s", url, content_path)
            return True, str(content_path)
        return False, f"request-error: {exc}"

    # 304 Not Modified -> use cached file if present
    if resp.status_code == 304:
        if content_path.exists():
            logger.info("Not modified (304): using cached file for %s", url)
            return True, str(content_path)
        logger.warning("Server returned 304 but cache file missing for %s; will attempt to GET body", url)

    # Non-2xx responses -> fallback to cache if present, otherwise fail
    if not (200 <= resp.status_code < 300):
        logger.warning("HTTP %s for %s", resp.status_code, url)
        if content_path.exists():
            logger.info("HTTP %s for %s — using cached file %s", resp.status_code, url, content_path)
            return True, str(content_path)
        return False, f"http-status:{resp.status_code}"

    # Write streamed content to temporary file then atomically replace content_path
    try:
        tmp = content_path.with_suffix(".dat.tmp")
        with tmp.open("wb") as fh:
            for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                if chunk:
                    fh.write(chunk)
        tmp.replace(content_path)
    except requests.exceptions.RequestException as exc:
        logger.warning("Stream error while fetching %s: %s", url, exc)
        if content_path.exists():
            logger.info("Falling back to cached file for %s -> %s", url, content_path)
            return True, str(content_path)
        return False, f"stream-error: {exc}"
    except Exception as exc:
        logger.exception("Error writing cache file for %s: %s", url, exc)
        if content_path.exists():
            return True, str(content_path)
        return False, f"write-error: {exc}"

    # Best-effort: write metadata (ETag, Last-Modified, fetched_at, etc.)
    new_meta = {
        "url": url,
        "fetched_at": int(time.time()),
        "etag": resp.headers.get("ETag"),
        "last_modified": resp.headers.get("Last-Modified"),
        "status_code": resp.status_code,
        "content_length": resp.headers.get("Content-Length"),
    }
    try:
        _write_meta(meta_json, new_meta)
    except Exception:
        logger.debug("Failed to write meta for %s", url)

    logger.info("Downloaded and cached %s -> %s", url, content_path)
    return True, str(content_path)


# -----------------------
# Utilities: cache inspection & pruning
# -----------------------
def cache_size_bytes(cache_dir: str) -> int:
    """Return total size (bytes) of files in the cache dir."""
    cd = Path(cache_dir)
    if not cd.exists():
        return 0
    total = 0
    for p in cd.rglob("*"):
        if p.is_file():
            try:
                total += p.stat().st_size
            except Exception:
                continue
    return total


def prune_cache(cache_dir: str, older_than_days: int = 60, remove_orphan_meta: bool = True) -> Dict[str, int]:
    """
    Prune cache files older than `older_than_days`. Optionally remove orphan meta files.

    Returns a dict with counts: {"deleted_files": N, "orphan_meta_deleted": M}
    """
    cd = Path(cache_dir)
    if not cd.exists():
        return {"deleted_files": 0, "orphan_meta_deleted": 0}
    cutoff = datetime.now() - timedelta(days=older_than_days)
    deleted = 0
    orphan_meta_deleted = 0

    # Delete .dat and .meta.json older than cutoff
    for p in list(cd.glob("*.dat")):
        try:
            mtime = datetime.fromtimestamp(p.stat().st_mtime)
            if mtime < cutoff:
                # remove associated meta as well
                key = p.stem  # <sha1>
                meta = cd / f"{key}.meta.json"
                try:
                    p.unlink()
                    deleted += 1
                except Exception:
                    pass
                try:
                    if meta.exists():
                        meta.unlink()
                except Exception:
                    pass
        except Exception:
            continue

    if remove_orphan_meta:
        for m in list(cd.glob("*.meta.json")):
            try:
                key = m.stem.replace(".meta", "")  # if name is "<sha1>.meta.json", stem is "<sha1>.meta"
                # compute corresponding dat name
                dat = cd / f"{key}.dat"
                if not dat.exists():
                    try:
                        m.unlink()
                        orphan_meta_deleted += 1
                    except Exception:
                        pass
            except Exception:
                continue

    return {"deleted_files": deleted, "orphan_meta_deleted": orphan_meta_deleted}


# -----------------------
# Command-line helper (opt-in)
# -----------------------
def _cli_inspect(cache_dir: str) -> None:
    cd = Path(cache_dir)
    print("Cache directory:", cd)
    print("Exists:", cd.exists())
    print("Total size (bytes):", cache_size_bytes(cache_dir))
    print("dat files:", len(list(cd.glob("*.dat"))) if cd.exists() else 0)
    print("meta.json files:", len(list(cd.glob("*.meta.json"))) if cd.exists() else 0)
    # show a small sample
    if cd.exists():
        sample = list(cd.glob("*.meta.json"))[:1]
        if sample:
            print("--- example meta ---")
            try:
                print(sample[0].read_text()[:400])
            except Exception:
                print("(could not read example meta)")


def _cli_prune(cache_dir: str, older_than_days: int, remove_orphan_meta: bool) -> None:
    print(f"Pruning cache {cache_dir}: older_than_days={older_than_days}, remove_orphan_meta={remove_orphan_meta}")
    r = prune_cache(cache_dir, older_than_days=older_than_days, remove_orphan_meta=remove_orphan_meta)
    print("Prune result:", r)


def _main_cli() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Inspect or prune the fetch cache (scripts/cache_utils.py)")
    ap.add_argument("--cache", default="output/cache", help="Cache directory")
    sub = ap.add_subparsers(dest="cmd", required=False)
    sub.add_parser("inspect", help="Print cache summary")
    pprune = sub.add_parser("prune", help="Prune old cache entries")
    pprune.add_argument("--days", type=int, default=60, help="Remove files older than DAYS")
    pprune.add_argument("--remove-orphan-meta", action="store_true", help="Remove meta files missing .dat counterpart")
    ap.add_argument("--verbose", action="store_true", help="Enable debug logs")
    args = ap.parse_args()

    set_log_level(args.verbose)

    if args.cmd == "prune":
        _cli_prune(args.cache, args.days, args.remove_orphan_meta)
    else:
        _cli_inspect(args.cache)


if __name__ == "__main__":
    _main_cli()
