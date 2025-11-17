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
IO_BUFFER_SIZE = utils.IO_BUFFER_SIZE

# Use utils implementations for consistency
_find_unescaped_char = utils.find_unescaped_char
_ELEMENT_HIDING_PATTERN = utils.ELEMENT_HIDING_PATTERN_RE  # Shared precompiled regex


def _contains_element_hiding_marker(s: str) -> bool:
    """Return True if the line contains element-hiding or scriptlet markers."""
    return bool(_ELEMENT_HIDING_PATTERN.search(s))


def _skip_regex_literal(s: str, opening_slash_idx: int) -> int:
    """
    Return the index immediately after the closing '/' of a regex literal.
    If the literal is unterminated, return -1 so the caller can abort trimming.
    """
    closing = _find_unescaped_char(s, "/", start=opening_slash_idx + 1)
    if closing == -1:
        return -1
    return closing + 1


def _strip_trailing_hash_safe(s: str) -> str:
    """
    Strip trailing inline comments introduced by '#'.

    A hash is treated as a comment marker only when it is the first unescaped '#'
    encountered outside a /regex literal/. The helper keeps '#':
      - inside balanced /regex/ segments,
      - that were escaped via '\\#',
      - or when the line contains element-hiding/scriptlet markers (##, #@#, #%#).
    Always rstrip whitespace from the returned string.
    """
    if not s:
        return ""

    # preserve element-hiding/scriptlet-containing lines as-is: validator handles them
    if _contains_element_hiding_marker(s):
        return s.rstrip()

    scan_idx = 0
    length = len(s)
    while scan_idx < length:
        hash_idx = _find_unescaped_char(s, "#", start=scan_idx)
        slash_idx = _find_unescaped_char(s, "/", start=scan_idx)

        # no further '#' characters -> nothing left to strip
        if hash_idx == -1:
            return s.rstrip()

        # first interesting char is '#': treat the rest as a comment
        if slash_idx == -1 or hash_idx < slash_idx:
            return s[:hash_idx].rstrip()

        # we saw a '/' before the '#'; treat it as the start of a /regex literal/
        regex_end = _skip_regex_literal(s, slash_idx)
        if regex_end == -1:
            # unterminated literal: conservatively keep the line intact
            return s.rstrip()
        scan_idx = regex_end

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
            (entry, out / entry.name) for entry in utils.list_text_rule_files(inp)
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
