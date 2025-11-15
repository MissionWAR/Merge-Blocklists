#!/usr/bin/env python3
"""
remove_comments.py

Strip comments and blank lines from blocklists.

Usage:
    python -m scripts.remove_comments INPUT OUTPUT
"""
from __future__ import annotations

import multiprocessing as mp
import sys
import tempfile
from os import PathLike
from pathlib import Path

from scripts import utils

# Import constants and utilities from utils to avoid duplication
ELEMENT_HIDING_MARKERS = utils.ELEMENT_HIDING_MARKERS
IO_BUFFER_SIZE = utils.IO_BUFFER_SIZE

# Use utils implementations for consistency
_find_unescaped_char = utils.find_unescaped_char
_ELEMENT_HIDING_PATTERN = utils.ELEMENT_HIDING_PATTERN_RE  # Shared precompiled regex


def _strip_trailing_hash_safe(s: str) -> str:
    """
    Strip trailing inline comments introduced by '#', while preserving text when:
      - The '#' appears inside a /regex literal/ (detected by matched unescaped '/').
      - The '#' is escaped ('\\#').

    Walk left-to-right, skipping balanced regex segments; the first unescaped '#'
    encountered outside a regex is treated as the start of a comment and trimmed.
    Always rstrip whitespace from the returned string.
    """
    if not s:
        return ""

    # preserve element-hiding/scriptlet-containing lines as-is: validator handles them
    # Optimized: use precompiled regex instead of 3 substring searches
    if _ELEMENT_HIDING_PATTERN.search(s):
        return s.rstrip()

    start = 0
    n = len(s)
    while start < n:
        pos_hash = _find_unescaped_char(s, "#", start=start)
        pos_slash = _find_unescaped_char(s, "/", start=start)

        # no hash at all -> nothing to strip
        if pos_hash == -1:
            return s.rstrip()

        # if there's no slash before the hash, the hash is outside any regex -> strip here
        if pos_slash == -1 or pos_hash < pos_slash:
            return s[:pos_hash].rstrip()

        # there's a slash before the hash -> find closing slash to skip the regex
        end_slash = _find_unescaped_char(s, "/", start=pos_slash + 1)
        if end_slash == -1:
            # unterminated regex: be conservative and don't chop anything
            return s.rstrip()
        # advance past the regex and keep scanning
        start = end_slash + 1

    return s.rstrip()


def _process_raw_line(raw_line: str) -> tuple[str | None, bool, str | None]:
    """
    Process a raw input line and return (cleaned_line, trimmed_flag, dropped_kind).
    dropped_kind ∈ {"empty", "comment", "empty_after_strip", None}.
    """
    # remove only newline characters here; we'll normalize other whitespace with .strip()
    raw_no_nl = raw_line.rstrip("\r\n")
    trimmed = raw_no_nl.strip()
    trimmed_flag = trimmed != raw_no_nl

    if not trimmed:
        return None, trimmed_flag, "empty"

    if utils.is_comment_line(trimmed):
        return None, trimmed_flag, "comment"

    cleaned = _strip_trailing_hash_safe(trimmed)
    if not cleaned.strip():
        return None, trimmed_flag, "empty_after_strip"

    return cleaned, trimmed_flag, None


def process_file(in_path: PathLike, out_path: PathLike) -> dict[str, int | str]:
    """
    Process one file and write cleaned output atomically.
    Returns per-file statistics.
    """
    in_path_p = Path(in_path)
    out_path_p = Path(out_path)
    stats: dict[str, int | str] = {
        "in_path": str(in_path_p),
        "out_path": str(out_path_p),
        "lines_in": 0,
        "lines_out": 0,
        "trimmed": 0,
        "dropped_comments": 0,
        "dropped_empty": 0,
    }

    # Ensure output parent dir exists
    out_parent = out_path_p.parent
    out_parent.mkdir(parents=True, exist_ok=True)

    # Atomic write using NamedTemporaryFile + replace
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=out_parent,
            prefix=".tmp_remove_",
            delete=False,
            buffering=IO_BUFFER_SIZE,  # 128KB buffer optimized for modern SSDs
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            with in_path_p.open(
                "r", encoding="utf-8", errors="surrogateescape", buffering=IO_BUFFER_SIZE
            ) as inp:
                for raw in inp:
                    stats["lines_in"] += 1
                    cleaned, trimmed_flag, dropped_kind = _process_raw_line(raw)
                    
                    # Track if line had whitespace trimmed
                    if trimmed_flag:
                        stats["trimmed"] += 1
                    
                    # Skip lines that should be dropped
                    if dropped_kind == "comment":
                        stats["dropped_comments"] += 1
                        continue
                    if dropped_kind in ("empty", "empty_after_strip"):
                        stats["dropped_empty"] += 1
                        continue
                    
                    # Write valid lines (cleaned is guaranteed non-None here)
                    tmp_file.write(cleaned + "\n")
                    stats["lines_out"] += 1
            tmp_file.flush()
            # NOTE: leaving replace() as-is (atomic rename) — this is POSIX-safe for GitHub runners.
            tmp_path.replace(out_path_p)
    except Exception:
        if tmp_path and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise

    return stats


def _process_file_worker(args: tuple[Path, Path]) -> dict[str, int | str]:
    """Worker function for parallel processing."""
    in_path, out_path = args
    return process_file(in_path, out_path)


def transform(
    input_path: PathLike, output_path: PathLike, parallel: bool = True
) -> list[dict[str, int | str]]:
    """
    Process either a single file or all .txt files in a directory.
    Returns a list of per-file statistics.
    
    Args:
        input_path: Input file or directory
        output_path: Output file or directory
        parallel: Use parallel processing for directories (default: True)
    """
    inp = Path(input_path)
    out = Path(output_path)
    results: list[dict[str, int | str]] = []

    if inp.is_dir():
        out.mkdir(parents=True, exist_ok=True)
        
        # Collect all files to process
        files_to_process = [
            (entry, out / entry.name)
            for entry in sorted(inp.iterdir(), key=lambda p: p.name.lower())
            if entry.is_file() and entry.name.lower().endswith(".txt")
        ]
        
        if not files_to_process:
            return results
        
        # Use parallel processing if enabled and multiple files
        if parallel and len(files_to_process) > 1:
            # Use all available CPU cores (no artificial cap)
            num_workers = min(mp.cpu_count(), len(files_to_process))
            with mp.Pool(processes=num_workers) as pool:
                results = pool.map(_process_file_worker, files_to_process)
        else:
            # Sequential processing (single file or parallel disabled)
            for in_path, out_path in files_to_process:
                results.append(process_file(in_path, out_path))
                
    elif inp.is_file():
        dest = out / inp.name if out.is_dir() else out
        dest.parent.mkdir(parents=True, exist_ok=True)
        results.append(process_file(inp, dest))
    else:
        raise FileNotFoundError(f"Input path not found: {input_path}")

    return results


def _print_summary(stats_list: list[dict[str, int | str]]) -> None:
    """Print aggregate statistics for all processed files."""
    total_in = sum(s["lines_in"] for s in stats_list)
    total_out = sum(s["lines_out"] for s in stats_list)
    total_trimmed = sum(s["trimmed"] for s in stats_list)
    total_comments = sum(s["dropped_comments"] for s in stats_list)
    total_empty = sum(s["dropped_empty"] for s in stats_list)
    print(
        f"remove_comments: files={len(stats_list)} "
        f"lines_in={total_in} lines_out={total_out} "
        f"trimmed={total_trimmed} dropped_comments={total_comments} dropped_empty={total_empty}"
    )


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m scripts.remove_comments INPUT OUTPUT")
        sys.exit(2)

    input_path_arg = sys.argv[1]
    output_path_arg = sys.argv[2]

    try:
        stats = transform(input_path_arg, output_path_arg)
        _print_summary(stats)
    except Exception as exc:
        print(f"ERROR in remove_comments: {exc}", file=sys.stderr)
        sys.exit(1)
