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
import os
import random
import shutil
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urljoin, urldefrag

import aiohttp

from scripts import utils
from scripts.cache_utils import CacheManager, atomic_write_text, hash_file


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


def _parse_filter_headers(path: Path, max_lines: int = 200) -> dict[str, str]:
    """Parse header directives (`! Key: Value`) from the start of a filter list."""
    directives: dict[str, str] = {}
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for _ in range(max_lines):
                line = fh.readline()
                if not line:
                    break
                if not line.startswith("!"):
                    break
                body = line[1:].strip()
                if ":" not in body:
                    continue
                key, value = body.split(":", 1)
                directives[key.strip().lower()] = value.strip()
    except OSError:
        return {}
    return directives


def _header_meta_from_directives(directives: dict[str, str]) -> dict[str, str | None]:
    """Extract cache metadata fields from parsed directives."""
    if not directives:
        return {}
    diff_path = directives.get("diff-path")
    checksum = directives.get("checksum")
    meta: dict[str, str | None] = {}
    if diff_path is not None:
        meta["diff_path"] = diff_path or None
    if checksum is not None:
        meta["list_checksum"] = checksum or None
    return meta


def _resolve_diff_url(list_url: str, diff_path: str) -> tuple[str, str | None]:
    """Return absolute patch URL and optional resource fragment from Diff-Path."""
    relative, fragment = urldefrag(diff_path.strip())
    if not relative:
        raise ValueError("Diff-Path is empty")
    patch_url = urljoin(list_url, relative)
    if not patch_url:
        raise ValueError("Unable to resolve Diff-Path")
    return patch_url, fragment or None


class DiffApplyError(Exception):
    """Raised when a diffupdate patch cannot be applied."""


def _parse_diff_blocks(diff_text: str) -> list[dict[str, Any]]:
    """Parse diffupdate file into discrete RCS blocks."""
    lines = diff_text.splitlines(keepends=True)
    blocks: list[dict[str, Any]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            i += 1
            continue
        if not stripped.lower().startswith("diff "):
            i += 1
            continue
        header_fields = stripped[4:].strip().split()
        header: dict[str, str] = {}
        for field in header_fields:
            if ":" not in field:
                continue
            key, value = field.split(":", 1)
            header[key.lower()] = value
        block = {
            "name": header.get("name"),
            "checksum": header.get("checksum"),
            "commands": [],
        }
        blocks.append(block)
        i += 1
        while i < len(lines):
            cmd_line = lines[i]
            cmd_stripped = cmd_line.strip()
            if cmd_stripped.lower().startswith("diff "):
                break
            if not cmd_stripped:
                i += 1
                continue
            if cmd_stripped.startswith(";") or cmd_stripped.startswith("#"):
                i += 1
                continue
            op = cmd_stripped[0].lower()
            if op not in ("a", "d"):
                raise DiffApplyError(f"Unsupported diff directive: {cmd_stripped}")
            remainder = cmd_stripped[1:].strip()
            parts = remainder.split()
            if len(parts) != 2:
                raise DiffApplyError(f"Malformed diff command: {cmd_stripped}")
            try:
                line_no = int(parts[0])
                count = int(parts[1])
            except ValueError as exc:
                raise DiffApplyError(f"Invalid diff command numbers: {cmd_stripped}") from exc
            i += 1
            payload: list[str] = []
            if op == "a":
                payload = lines[i : i + count]
                if len(payload) < count:
                    raise DiffApplyError("Diff file truncated while reading additions")
                i += count
            block["commands"].append((op, line_no, count, payload))
        # Inner while exits when next diff block encountered
    return blocks


def _apply_rcs_commands(original: list[str], commands: list[tuple[str, int, int, list[str]]]) -> list[str]:
    """Apply RCS a/d commands to a list of lines."""
    lines = list(original)
    for op, line_no, count, payload in commands:
        if op == "d":
            start = line_no - 1
            if count < 0 or start < 0 or start + count > len(lines):
                raise DiffApplyError("Delete command out of range")
            del lines[start : start + count]
        elif op == "a":
            insert_at = line_no
            if count < 0 or insert_at < 0 or insert_at > len(lines):
                raise DiffApplyError("Add command out of range")
            lines[insert_at:insert_at] = payload
        else:
            raise DiffApplyError(f"Unsupported op: {op}")
    return lines


def _apply_diff_patch(
    cached_file: Path, diff_text: str, resource_name: str | None
) -> str:
    """Apply diffupdate patch text to cached_file and return patched content."""
    try:
        original = cached_file.read_text(encoding="utf-8", errors="replace").splitlines(
            keepends=True
        )
    except OSError as exc:
        raise DiffApplyError(f"Unable to read cached file: {exc}") from exc

    blocks = _parse_diff_blocks(diff_text)
    if not blocks:
        raise DiffApplyError("Patch file contains no diff blocks")

    block = None
    if resource_name:
        for candidate in blocks:
            if candidate.get("name") == resource_name:
                block = candidate
                break
        if block is None:
            raise DiffApplyError(f"No diff block found for resource '{resource_name}'")
    else:
        block = blocks[0]

    commands = block.get("commands", [])
    patched = _apply_rcs_commands(original, commands)
    patched_text = "".join(patched)

    checksum = block.get("checksum")
    if checksum:
        sha1 = hashlib.sha1(patched_text.encode("utf-8")).hexdigest()
        if sha1.lower() != checksum.lower():
            raise DiffApplyError("Checksum mismatch after applying patch")

    return patched_text


def _log_diff_failure(url: str, reason: str) -> None:
    """Log diffupdate failure reasons without aborting the pipeline."""
    print(f"[diffupdates] {url}: {reason}", file=sys.stderr)


async def _download_patch_text(
    session: aiohttp.ClientSession,
    patch_url: str,
    timeout: int,
    per_host_delay: float,
    host_last_times: dict[str, float],
) -> str | None:
    """Download patch text, returning None if not available."""
    origin = _get_origin(patch_url)
    await _wait_for_host_slot(origin, host_last_times, per_host_delay)
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; MergeBlocklists/1.0; +https://github.com/filterlists-aggregator)"
    }
    timeout_obj = aiohttp.ClientTimeout(
        total=timeout,
        connect=10,
        sock_read=timeout,
    )
    async with session.get(
        patch_url,
        headers=headers,
        timeout=timeout_obj,
        allow_redirects=True,
        max_redirects=10,
    ) as resp:
        host_last_times[origin] = time.time()
        if resp.status in (204, 404):
            return None
        if resp.status != 200:
            raise DiffApplyError(f"Patch request failed with HTTP {resp.status}")
        text = await resp.text(encoding="utf-8", errors="replace")
        if not text.strip():
            return None
        return text


async def _try_diff_update(
    session: aiohttp.ClientSession,
    url: str,
    cache: CacheManager,
    cached_file: Path,
    diff_path: str,
    dest_path: Path,
    timeout: int,
    per_host_delay: float,
    host_last_times: dict[str, float],
) -> bool:
    """Attempt to update cached_file using diffupdates (intentional incremental support). Returns True on success."""
    diff_path = diff_path.strip()
    if not diff_path:
        return False
    try:
        patch_url, resource_name = _resolve_diff_url(url, diff_path)
    except ValueError as exc:
        _log_diff_failure(url, f"invalid Diff-Path: {exc}")
        return False

    try:
        patch_text = await _download_patch_text(
            session, patch_url, timeout, per_host_delay, host_last_times
        )
    except asyncio.TimeoutError:
        _log_diff_failure(url, "patch download timed out")
        return False
    except aiohttp.ClientError as exc:
        _log_diff_failure(url, f"patch download failed: {type(exc).__name__}")
        return False
    except DiffApplyError as exc:
        _log_diff_failure(url, str(exc))
        return False

    if not patch_text:
        _log_diff_failure(url, "patch not available")
        return False

    try:
        patched_text = _apply_diff_patch(cached_file, patch_text, resource_name)
    except DiffApplyError as exc:
        _log_diff_failure(url, str(exc))
        return False
    except Exception as exc:
        _log_diff_failure(url, f"patch apply error: {exc}")
        return False

    tmp = cached_file.with_suffix(".part")
    content_bytes = patched_text.encode("utf-8")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tmp.open("wb") as fh:
            fh.write(content_bytes)
        tmp.replace(cached_file)
    except OSError as exc:
        _log_diff_failure(url, f"failed to store patched file: {exc}")
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
        return False

    try:
        _sync_cache_to_dest(cached_file, dest_path)
    except Exception as exc:
        _log_diff_failure(url, f"failed to sync patched list: {exc}")
        return False

    directives = _parse_filter_headers(cached_file)
    header_meta = _header_meta_from_directives(directives)
    content_sha = hashlib.sha256(content_bytes).hexdigest()
    updates: dict[str, Any] = {
        "content_sha256": content_sha,
        "fetched_at": int(time.time()),
        "status_code": 226,
    }
    updates.update(header_meta)
    try:
        cache.update_meta(url, updates, autosave=False)
    except Exception as exc:
        _log_diff_failure(url, f"failed to update cache metadata: {exc}")
        return False

    return True

def _sync_cache_to_dest(cache_path: Path, dest_path: Path) -> None:
    """Reuse cached file contents in out_dir via hardlink when possible, else copy."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    if dest_path.exists():
        try:
            if dest_path.samefile(cache_path):
                return  # already pointing to the same inode
        except (OSError, AttributeError):
            pass
        try:
            dest_path.unlink()
        except OSError:
            pass
    try:
        os.link(cache_path, dest_path)
    except OSError:
        shutil.copy2(cache_path, dest_path)


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
    cached_file = cache.get_cached_file(url)
    cache_path = cached_file or cache.path_for_url(url)
    dest_path = out_dir / cache_path.name

    origin = _get_origin(url)
    meta = cache.get_meta(url) or {}
    etag, last_modified = meta.get("etag"), meta.get("last_modified")
    header_directives = _parse_filter_headers(cached_file) if cached_file else {}
    diff_path = None
    if cached_file:
        diff_path = header_directives.get("diff-path") or meta.get("diff_path")

    # Track per-origin delay in session object
    if not hasattr(session, "_host_last_times"):
        session._host_last_times = {}  # type: ignore
    host_last_times: dict[str, float] = session._host_last_times  # type: ignore

    if cached_file and diff_path:
        diff_updated = await _try_diff_update(
            session,
            url,
            cache,
            cached_file,
            diff_path,
            dest_path,
            timeout,
            per_host_delay,
            host_last_times,
        )
        if diff_updated:
            return "ok", url, str(dest_path)

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

            # Set comprehensive timeout (connect, read, total)
            timeout_obj = aiohttp.ClientTimeout(
                total=timeout,
                connect=10,  # 10s to establish connection
                sock_read=timeout  # timeout for reading response
            )
            async with session.get(
                url, 
                headers=headers, 
                timeout=timeout_obj,
                allow_redirects=True,  # Follow redirects (max 10 by default)
                max_redirects=10
            ) as resp:
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
                        header_meta = _header_meta_from_directives(header_directives)
                        cache.record_fetch(
                            url,
                            cached_file,
                            etag=resp_etag,
                            last_modified=resp_last_modified,
                            content_sha256=content_sha,
                            status_code=resp.status,
                            autosave=False,
                            extra=header_meta or None,
                        )
                        _sync_cache_to_dest(cached_file, dest_path)
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
                directives = _parse_filter_headers(cache_path)
                header_meta = _header_meta_from_directives(directives)

                cache.record_fetch(
                    url,
                    cache_path,
                    etag=resp_etag,
                    last_modified=resp_last_modified,
                    content_sha256=content_sha,
                    status_code=resp.status,
                    autosave=False,
                    extra=header_meta or None,
                )

                _sync_cache_to_dest(cache_path, dest_path)
                return "ok", url, str(dest_path)

        except asyncio.TimeoutError:
            last_exc = Exception("Timeout - server did not respond in time")
            if attempt <= retries:
                base = 0.5 * (2 ** (attempt - 1))
                jitter = random.uniform(0, base * 0.1)
                await asyncio.sleep(min(base + jitter, 10.0))
                continue
            break
        except aiohttp.ClientConnectionError as ex:
            last_exc = Exception(f"Connection error - {type(ex).__name__}")
            if attempt <= retries:
                base = 0.5 * (2 ** (attempt - 1))
                jitter = random.uniform(0, base * 0.1)
                await asyncio.sleep(min(base + jitter, 10.0))
                continue
            break
        except aiohttp.ClientSSLError as ex:
            last_exc = Exception(f"SSL certificate error - {ex}")
            # SSL errors are usually not transient, don't retry
            break
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
            _sync_cache_to_dest(cached, dest_path)
            return "used-cache-on-fail", url, str(dest_path)
        except Exception as ex:
            return "failed", url, f"fallback copy error: {ex}"
    # Provide detailed error message
    error_msg = str(last_exc) if last_exc else "unknown error"
    return "failed", url, error_msg


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

    # Configure connector with better error handling
    connector = aiohttp.TCPConnector(
        limit=concurrency,
        limit_per_host=5,  # Max 5 concurrent connections per host
        ttl_dns_cache=300,  # Cache DNS for 5 minutes
        force_close=False,  # Reuse connections
        enable_cleanup_closed=True  # Clean up closed connections
    )
    sem = asyncio.Semaphore(concurrency)

    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                asyncio.create_task(
                    _fetch_with_limit(
                        session,
                        sem,
                        url,
                        cache,
                        out_dir,
                        timeout,
                        retries,
                        per_host_delay,
                    )
                )
                for url in urls
            ]

            for coro in asyncio.as_completed(tasks):
                status, url, info = await coro
                results["processed"] += 1
                results[status] = results.get(status, 0) + 1

                # Track failures for summary report (don't log immediately to avoid duplicates)
                if status == "failed":
                    failed_urls.append((url, info))
    finally:
        cache.save()

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
                sha = hash_file(p)
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
