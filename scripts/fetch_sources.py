#!/usr/bin/env python3
"""
scripts/fetch_sources.py

Fetch sources into cache and produce a concatenated raw output file.

Key behaviors:
- Defaults to sequential downloading (concurrency=1). Use --concurrency to enable
  bounded parallelism.
- Per-host concurrency and a per-host minimum interval prevent hammering single hosts.
- Uses the cache utilities in scripts/cache_utils.py (ETag/If-Modified-Since support).
- Optional --dry-run / --verify-only to only inspect cache without hitting network.
- --verbose to enable debug logging.

Example:
  python3 -m scripts.fetch_sources --workdir . --cache output/cache --out output/_raw.txt
  python3 -m scripts.fetch_sources --dry-run --cache output/cache
"""

from __future__ import annotations

import argparse
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import sys

# make sure repo root is on sys.path so "from scripts import cache_utils" works
_THIS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _THIS_DIR.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts import cache_utils  # local module with download_with_cache(), session_with_retries(), _key(), _read_meta_any

# module logger
logger = logging.getLogger("fetch_sources")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)


def set_log_level(verbose: bool) -> None:
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    cache_utils.set_log_level(verbose)


def read_sources_file(path: Path) -> List[str]:
    """Return list of non-empty, non-comment lines from a sources file."""
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [ln.strip() for ln in text.splitlines()]
    return [ln for ln in lines if ln and not ln.startswith("#") and not ln.startswith("!")]


def _worker_download(
    session,
    url: str,
    cache_dir: str,
    timeout: int,
    host_semaphores: Dict[str, threading.Semaphore],
    host_timestamps: Dict[str, float],
    host_lock: threading.Lock,
    min_per_host_interval: float,
    per_host: int,
    max_bytes: int,
    dry_run: bool = False,
) -> Tuple[bool, Optional[str], bool, Optional[str]]:
    """
    Download a single URL into cache (or inspect cache if dry_run).

    Returns:
      (ok, path_or_none, was_cached, error_or_none)
    """
    parsed = urlparse(url)
    host = parsed.hostname or url

    sem = host_semaphores.setdefault(host, threading.Semaphore(per_host))
    acquired = sem.acquire(timeout=5)
    if not acquired:
        return False, None, False, "host-busy"

    try:
        # Enforce min interval between hits to same host
        with host_lock:
            last_ts = host_timestamps.get(host, 0.0)
            now = time.time()
            wait = 0.0
            if min_per_host_interval and (now - last_ts) < min_per_host_interval:
                wait = min_per_host_interval - (now - last_ts)
        if wait:
            logger.debug("Waiting %.2fs before contacting host %s", wait, host)
            time.sleep(wait)

        key = cache_utils._key(url)
        content_path = Path(cache_dir) / f"{key}.dat"
        meta_path = Path(cache_dir) / f"{key}.meta.json"

        # Dry-run simply checks cache presence
        if dry_run:
            cached_exists = content_path.exists()
            return True, str(content_path) if cached_exists else None, cached_exists, None

        # If cache missing and max_bytes is set, optionally HEAD-check to skip large files
        need_head_check = not content_path.exists() and bool(max_bytes and max_bytes > 0)
        if need_head_check and hasattr(session, "head"):
            try:
                logger.debug("HEAD %s", url)
                resp_head = session.head(url, allow_redirects=True, timeout=min(10, timeout))
                cl = resp_head.headers.get("Content-Length")
                if cl and int(cl) > max_bytes:
                    return False, None, False, f"too-large:{cl}"
            except Exception as exc:
                logger.debug("HEAD failed for %s: %s", url, exc)

        # Read old meta (if any) for hit detection
        try:
            old_meta = cache_utils._read_meta_any(meta_path)
        except Exception:
            old_meta = {}

        ok, path_or_err = cache_utils.download_with_cache(session, url, cache_dir, timeout=timeout)

        # Update host timestamp
        with host_lock:
            host_timestamps[host] = time.time()

        if not ok:
            return False, None, False, path_or_err

        # Read new meta and decide if this was a cached hit
        try:
            new_meta = cache_utils._read_meta_any(meta_path)
        except Exception:
            new_meta = {}

        was_cached = False
        # If both have fetched_at and they are the same, consider it cached (server returned 304)
        if old_meta and new_meta and old_meta.get("fetched_at") and new_meta.get("fetched_at"):
            if old_meta.get("fetched_at") == new_meta.get("fetched_at"):
                was_cached = True
        else:
            # If no meta, but content existed prior to call, guess cached hit (best-effort)
            if content_path.exists() and old_meta:
                was_cached = True

        return True, path_or_err, was_cached, None
    finally:
        sem.release()


def _mirror_and_collect(raw_parts_dir: Path, content_path: Path, out_lines: List[str]) -> None:
    """
    Copy content to raw_parts for provenance and append non-comment lines into out_lines.
    Best-effort: failures here don't abort the run.
    """
    raw_parts_dir.mkdir(parents=True, exist_ok=True)
    target = raw_parts_dir / content_path.name
    try:
        data = content_path.read_text(encoding="utf-8", errors="replace")
        target.write_text(data, encoding="utf-8")
    except Exception as exc:
        logger.debug("Mirror failed for %s -> %s: %s", content_path, target, exc)
        return

    for ln in data.splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or s.startswith("!"):
            continue
        out_lines.append(ln)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Fetch sources into cache and produce concatenated raw output.")
    p.add_argument("--workdir", default=".", help="Repository root (where sources.txt lives)")
    p.add_argument("--sources", default="sources.txt", help="Sources file path (relative to workdir)")
    p.add_argument("--cache", default="output/cache", help="Cache directory")
    p.add_argument("--raw-parts", default="output/raw_parts", help="Directory to mirror raw downloaded parts")
    p.add_argument("--out", default="output/_raw.txt", help="Concatenated output file")
    p.add_argument("--concurrency", type=int, default=1, help="Total workers (1 = sequential)")
    p.add_argument("--per-host", type=int, default=2, help="Max concurrent requests per hostname")
    p.add_argument("--min-per-host-interval", type=float, default=0.5, help="Min seconds between requests to same host")
    p.add_argument("--timeout", type=int, default=30, help="Per-request timeout (seconds)")
    p.add_argument("--max-bytes", type=int, default=0, help="Skip downloads whose Content-Length exceeds this size (0=disabled)")
    p.add_argument("--dry-run", action="store_true", help="Do not perform network requests; only report cache hits")
    p.add_argument("--verify-only", action="store_true", help="Alias for --dry-run")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging (verbose)")
    args = p.parse_args(argv)

    set_log_level(args.verbose)

    workdir = Path(args.workdir)
    sources_path = (workdir / args.sources).resolve()
    cache_dir = (workdir / args.cache).resolve()
    raw_parts_dir = (workdir / args.raw_parts).resolve()
    out_path = (workdir / args.out).resolve()

    if not sources_path.exists():
        logger.error("Sources file not found: %s", sources_path)
        return 1

    urls = read_sources_file(sources_path)
    if not urls:
        logger.info("No sources to process.")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("", encoding="utf-8")
        return 0

    # session only when not dry-run
    session = None
    if not (args.dry_run or args.verify_only):
        session = cache_utils.session_with_retries()

    host_semaphores: Dict[str, threading.Semaphore] = {}
    host_timestamps: Dict[str, float] = {}
    host_lock = threading.Lock()

    out_lines: List[str] = []
    failures: List[Tuple[str, str]] = []
    cached_hits = 0
    downloads = 0
    total = len(urls)

    # sequential or threaded execution
    if args.concurrency <= 1:
        for url in urls:
            ok, path_or_err, was_cached, err = _worker_download(
                session,
                url,
                str(cache_dir),
                args.timeout,
                host_semaphores,
                host_timestamps,
                host_lock,
                args.min_per_host_interval,
                args.per_host,
                args.max_bytes,
                dry_run=(args.dry_run or args.verify_only),
            )
            if not ok:
                failures.append((url, err or "unknown"))
                continue
            if path_or_err:
                if was_cached:
                    cached_hits += 1
                else:
                    downloads += 1
                try:
                    _mirror_and_collect(raw_parts_dir, Path(path_or_err), out_lines)
                except Exception as exc:
                    logger.debug("mirror error for %s: %s", path_or_err, exc)
            else:
                logger.info("No cached file for %s (dry-run)", url)
    else:
        with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
            fut_to_url = {}
            for url in urls:
                fut = ex.submit(
                    _worker_download,
                    session,
                    url,
                    str(cache_dir),
                    args.timeout,
                    host_semaphores,
                    host_timestamps,
                    host_lock,
                    args.min_per_host_interval,
                    args.per_host,
                    args.max_bytes,
                    args.dry_run or args.verify_only,
                )
                fut_to_url[fut] = url
            for fut in as_completed(fut_to_url):
                url = fut_to_url[fut]
                try:
                    ok, path_or_err, was_cached, err = fut.result()
                except Exception as exc:
                    failures.append((url, f"exception: {exc}"))
                    continue
                if not ok:
                    failures.append((url, err or "unknown"))
                    continue
                if path_or_err:
                    if was_cached:
                        cached_hits += 1
                    else:
                        downloads += 1
                    try:
                        _mirror_and_collect(raw_parts_dir, Path(path_or_err), out_lines)
                    except Exception as exc:
                        logger.debug("mirror error for %s: %s", path_or_err, exc)
                else:
                    logger.info("No cached file for %s (dry-run)", url)

    # write final concatenated output (non-empty, non-comment lines)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    final_text = "\n".join(out_lines).rstrip() + "\n"
    out_path.write_text(final_text, encoding="utf-8")

    succeeded = cached_hits + downloads
    logger.info(
        "Fetch summary: sources=%d, succeeded=%d, cached_hits=%d, downloads=%d, failures=%d",
        total,
        succeeded,
        cached_hits,
        downloads,
        len(failures),
    )
    if failures:
        logger.info("Failed (sample):")
        for u, err in failures[:20]:
            logger.info("- %s -> %s", u, err)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
