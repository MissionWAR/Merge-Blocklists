#!/usr/bin/env python3
"""
fetch_sources.py

Asynchronous downloader for blocklist sources with built-in caching and retry logic.

Behavior:
 - Uses aiohttp for concurrent downloads.
 - Respects simple per-origin rate limiting (delay between requests to same origin).
 - Supports conditional GET (If-None-Match / If-Modified-Since) using cached metadata.
 - Falls back to cached file on failure or 304 Not Modified.
 - Retries transient failures (network, 429, 5xx) with exponential backoff + jitter.
 - Deduplicates fetched .txt files by content hash after completion.
 - Writes structured JSON summary to cache directory.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import random
import shutil
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp

from scripts import utils
from scripts.cache_utils import CacheManager, atomic_write_text


# ----------------------------------------
# Constants
# ----------------------------------------
IO_BUFFER_SIZE = utils.IO_BUFFER_SIZE  # Import shared buffer size for consistency
CHUNK_SIZE = IO_BUFFER_SIZE  # Use same buffer size for network chunks
PURGE_TOKENS = ("_clean", "_valid", ".part", ".bak", ".swp")

# CI-safe defaults
DEFAULT_CONCURRENCY = 8
DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 3
DEFAULT_PER_HOST_DELAY = 0.2  # seconds


# ----------------------------------------
# Helpers
# ----------------------------------------
def _get_origin(url: str) -> str:
    """Return canonical origin (scheme://host[:port]) for rate limiting."""
    p = urlparse(url)
    scheme = p.scheme or "https"
    host = p.hostname or ""
    port = f":{p.port}" if p.port else ""
    return f"{scheme}://{host}{port}"


async def _wait_for_host_slot(
    origin: str, host_last_times: dict[str, float], delay: float
) -> None:
    """Ensure at least `delay` seconds since last request to the same origin."""
    now = time.time()
    last = host_last_times.get(origin, 0.0)
    wait = delay - (now - last)
    if wait > 0:
        await asyncio.sleep(wait)
    # Caller updates host_last_times[origin] after actual request


def _should_retry_status(status: int) -> bool:
    """Return True if HTTP status is retryable."""
    return status == 429 or 500 <= status < 600


def compute_file_sha(path: Path) -> str:
    """Compute SHA-256 of a file (used for deduplication)."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


# ----------------------------------------
# Fetch single URL
# ----------------------------------------
async def fetch_one(
    session: aiohttp.ClientSession,
    url: str,
    cache: CacheManager,
    out_dir: Path,
    timeout: int,
    retries: int,
    per_host_delay: float,
) -> tuple[str, str, str]:
    """
    Fetch a single URL with conditional GET and retries.

    Returns tuple: (status, url, info)
      status ∈ {"ok", "not-modified", "used-cache-on-fail", "failed"}
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache.path_for_url(url)
    dest_path = out_dir / cache_path.name

    origin = _get_origin(url)
    meta = cache.get_meta(url) or {}
    cached_file = cache.get_cached_file(url)
    etag, last_modified = meta.get("etag"), meta.get("last_modified")

    # Track per-origin delay in session object
    if not hasattr(session, "_host_last_times"):
        session._host_last_times = {}  # type: ignore
    host_last_times: dict[str, float] = session._host_last_times  # type: ignore

    attempt = 0
    last_exc: Exception | None = None

    while attempt <= retries:
        attempt += 1
        try:
            # Respect per-origin delay
            await _wait_for_host_slot(origin, host_last_times, per_host_delay)

            headers: dict[str, str] = {
                "User-Agent": "Mozilla/5.0 (compatible; MergeBlocklists/1.0; +https://github.com/filterlists-aggregator)"
            }
            if etag:
                headers["If-None-Match"] = etag
            if last_modified:
                headers["If-Modified-Since"] = last_modified

            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with session.get(url, headers=headers, timeout=timeout_obj) as resp:
                # update last request time for origin
                host_last_times[origin] = time.time()

                # 304: not modified, re-use cached copy
                if resp.status == 304:
                    if cached_file and cached_file.exists():
                        # refresh metadata from response headers if present
                        resp_etag = resp.headers.get("ETag") or etag
                        resp_last_modified = (
                            resp.headers.get("Last-Modified") or last_modified
                        )
                        # Reuse existing SHA from metadata (file hasn't changed)
                        content_sha = meta.get("content_sha256")
                        cache.record_fetch(
                            url,
                            cached_file,
                            etag=resp_etag,
                            last_modified=resp_last_modified,
                            content_sha256=content_sha,
                            status_code=resp.status,
                        )
                        shutil.copy2(cached_file, dest_path)
                        return "not-modified", url, str(dest_path)
                    last_exc = Exception("304 received but no cached copy available")
                    raise last_exc

                # Non-200: handle retryable or final failure
                if resp.status != 200:
                    if _should_retry_status(resp.status):
                        last_exc = Exception(f"HTTP {resp.status}")
                        raise last_exc
                    last_exc = Exception(f"HTTP {resp.status}")
                    break

                # 200 OK: stream download to temp file + compute SHA
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                tmp = cache_path.with_suffix(".part")
                hasher = hashlib.sha256()
                with tmp.open("wb") as fh:
                    async for chunk in resp.content.iter_chunked(CHUNK_SIZE):
                        if not chunk:
                            continue
                        fh.write(chunk)
                        hasher.update(chunk)

                # atomic replace cached file
                tmp.replace(cache_path)

                resp_etag = resp.headers.get("ETag")
                resp_last_modified = resp.headers.get("Last-Modified")
                content_sha = hasher.hexdigest()

                cache.record_fetch(
                    url,
                    cache_path,
                    etag=resp_etag,
                    last_modified=resp_last_modified,
                    content_sha256=content_sha,
                    status_code=resp.status,
                )

                shutil.copy2(cache_path, dest_path)
                return "ok", url, str(dest_path)

        except Exception as ex:
            last_exc = ex
            if attempt <= retries:
                base = 0.5 * (2 ** (attempt - 1))
                jitter = random.uniform(0, base * 0.1)
                await asyncio.sleep(min(base + jitter, 10.0))
                continue
            break

    # After all retries fail: fallback to cached file
    cached = cache.get_cached_file(url)
    if cached and cached.exists():
        try:
            shutil.copy2(cached, dest_path)
            return "used-cache-on-fail", url, str(dest_path)
        except Exception as ex:
            return "failed", url, f"fallback copy error: {ex}"
    return "failed", url, f"failed: {last_exc}"


# ----------------------------------------
# Fetch all URLs concurrently
# ----------------------------------------
async def fetch_all(
    urls: list[str],
    out_dir: Path,
    cache_dir: Path,
    concurrency: int,
    timeout: int,
    retries: int,
    per_host_delay: float,
) -> dict[str, Any]:
    """Fetch all sources concurrently and summarize results."""
    cache = CacheManager(cache_dir)
    results: dict[str, int] = {
        "ok": 0,
        "not-modified": 0,
        "used-cache-on-fail": 0,
        "failed": 0,
        "processed": 0,
    }
    failed_urls: list[tuple[str, str]] = []  # Track failed URLs with reasons

    connector = aiohttp.TCPConnector(limit=concurrency)
    sem = asyncio.Semaphore(concurrency)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            asyncio.create_task(
                _fetch_with_limit(
                    session, sem, url, cache, out_dir, timeout, retries, per_host_delay
                )
            )
            for url in urls
        ]

        for coro in asyncio.as_completed(tasks):
            status, url, info = await coro
            results["processed"] += 1
            results[status] = results.get(status, 0) + 1
            
            # Only log failures (reduce log noise)
            if status == "failed":
                failed_urls.append((url, info))
                print(f"❌ [FAILED] {url} -> {info}")

    # Write summary JSON into cache dir
    summary = {"summary": results, "timestamp": int(time.time())}
    try:
        atomic_write_text(
            Path(cache_dir) / "fetch_summary.json",
            json.dumps(summary, indent=2, ensure_ascii=False),
        )
    except Exception:
        pass

    # Post-cleanup (non-fatal)
    try:
        purge_processed_like_files(out_dir)
        dedupe_outdir_by_content(out_dir)
    except Exception as e:
        import sys
        print(f"Warning: Post-cleanup failed: {e}", file=sys.stderr)

    return {
        "results": results,
        "failed_urls": failed_urls,
        "cache_dir": str(cache_dir),
        "out_dir": str(out_dir),
    }


async def _fetch_with_limit(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    url: str,
    cache: CacheManager,
    out_dir: Path,
    timeout: int,
    retries: int,
    per_host_delay: float,
) -> tuple[str, str, str]:
    """Run fetch_one() under concurrency semaphore."""
    async with sem:
        return await fetch_one(
            session, url, cache, out_dir, timeout, retries, per_host_delay
        )


# ----------------------------------------
# Post-processing
# ----------------------------------------
def purge_processed_like_files(out_dir: Path) -> None:
    """Delete leftover temporary or auxiliary files."""
    out_dir_path = Path(out_dir)
    if not out_dir_path.exists():
        return
    for p in out_dir_path.iterdir():
        if p.is_file() and any(tok in p.name.lower() for tok in PURGE_TOKENS):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass


def dedupe_outdir_by_content(out_dir: Path) -> None:
    """Deduplicate .txt files in output directory by SHA-256 hash."""
    out_dir_path = Path(out_dir)
    if not out_dir_path.exists():
        return
    files = [p for p in out_dir_path.iterdir() if p.is_file() and p.suffix == ".txt"]
    if len(files) <= 1:
        return

    # Group by file size to minimize hashing
    size_map: dict[int, list[Path]] = {}
    for p in files:
        try:
            size_map.setdefault(p.stat().st_size, []).append(p)
        except Exception:
            continue

    sha_map: dict[str, list[Path]] = {}
    for group in size_map.values():
        for p in group:
            try:
                sha = compute_file_sha(p)
                sha_map.setdefault(sha, []).append(p)
            except Exception:
                continue

    for paths in sha_map.values():
        if len(paths) <= 1:
            continue
        keeper = sorted(paths, key=lambda p: (len(p.name), p.name))[0]
        for p in paths:
            if p != keeper:
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    pass


# ----------------------------------------
# CLI
# ----------------------------------------
def main() -> None:
    """CLI entrypoint for async source fetching."""
    parser = argparse.ArgumentParser(
        description="Fetch blocklist sources (async, with cache fallback)"
    )
    parser.add_argument(
        "-s", "--sources", default="sources.txt", help="File with source URLs"
    )
    parser.add_argument("-o", "--outdir", default="lists/_raw", help="Output directory")
    parser.add_argument("-c", "--cache", default=".cache", help="Cache directory")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help="Max concurrent fetches",
    )
    parser.add_argument(
        "--retries", type=int, default=DEFAULT_RETRIES, help="Retries per URL"
    )
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout (seconds)"
    )
    parser.add_argument(
        "--per-host-delay",
        type=float,
        default=DEFAULT_PER_HOST_DELAY,
        help="Delay between requests to same host (seconds)",
    )
    args = parser.parse_args()

    src = Path(args.sources)
    if not src.exists():
        raise SystemExit(f"Sources file not found: {src}")
    with src.open("r", encoding="utf-8") as fh:
        urls = [
            line.strip() for line in fh if line.strip() and not line.startswith("#")
        ]

    out_dir = Path(args.outdir)
    cache_dir = Path(args.cache)

    info = asyncio.run(
        fetch_all(
            urls,
            out_dir,
            cache_dir,
            args.concurrency,
            args.timeout,
            args.retries,
            args.per_host_delay,
        )
    )
    res = info["results"]
    failed_urls = info.get("failed_urls", [])

    print("fetch_sources: finished")
    print(f"  processed:           {res['processed']}")
    print(f"    ok:                {res['ok']}")
    print(f"    not-modified:      {res.get('not-modified', 0)}")
    print(f"    used-cache-on-fail:{res['used-cache-on-fail']}")
    print(f"    failed:            {res['failed']}")
    
    # Show failed URLs if any
    if failed_urls:
        print("\n⚠️  Failed URLs:")
        for url, reason in failed_urls:
            print(f"  - {url}")
            print(f"    Reason: {reason}")


if __name__ == "__main__":
    main()
