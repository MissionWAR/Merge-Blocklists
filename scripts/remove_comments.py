#!/usr/bin/env python3
"""
remove_comments.py

Strip comments and blank lines from blocklists.

Usage:
    python -m scripts.remove_comments INPUT OUTPUT
"""

from __future__ import annotations

import logging
import sys
import tempfile
from os import PathLike
from pathlib import Path

from scripts import utils

# Import constants and utilities from utils to avoid duplication
IO_BUFFER_SIZE = utils.IO_BUFFER_SIZE


# Use utils implementations for consistency
_find_unescaped_char = utils.find_unescaped_char

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s"
)
logger = logging.getLogger(__name__)
RC_KEYS = utils.REMOVE_COMMENTS_STATS_KEYS




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
    if utils.is_element_hiding_rule(s):
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
    # remove only newline chars; normalize other whitespace with .strip()
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
        RC_KEYS.LINES_IN: 0,
        RC_KEYS.LINES_OUT: 0,
        RC_KEYS.TRIMMED: 0,
        RC_KEYS.DROPPED_COMMENTS: 0,
        RC_KEYS.DROPPED_EMPTY: 0,
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
                "r",
                encoding="utf-8",
                errors="surrogateescape",
                buffering=IO_BUFFER_SIZE,
            ) as inp:
                for raw in inp:
                    stats[RC_KEYS.LINES_IN] += 1
                    cleaned, trimmed_flag, dropped_kind = _process_raw_line(raw)

                    # Track if line had whitespace trimmed
                    if trimmed_flag:
                        stats[RC_KEYS.TRIMMED] += 1

                    # Skip lines that should be dropped
                    if dropped_kind == "comment":
                        stats[RC_KEYS.DROPPED_COMMENTS] += 1
                        continue
                    if dropped_kind in ("empty", "empty_after_strip"):
                        stats[RC_KEYS.DROPPED_EMPTY] += 1
                        continue

                    # Write valid lines (cleaned is guaranteed non-None here)
                    tmp_file.write(cleaned + "\n")
                    stats[RC_KEYS.LINES_OUT] += 1
            tmp_file.flush()
            # NOTE: replace() provides atomic rename; POSIX-safe for GitHub runners.
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


def _build_job_args(in_path: Path, out_path: Path) -> tuple[Path, Path]:
    """Return argument tuple for the worker (preserves type for pickling)."""
    return in_path, out_path


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
    if inp.is_dir():
        out.mkdir(parents=True, exist_ok=True)
    return utils.process_text_rule_files(
        inp,
        out,
        job_builder=_build_job_args,
        worker=_process_file_worker,
        parallel=parallel,
    )


def _print_summary(stats_list: list[dict[str, int | str]]) -> None:
    """Print aggregate statistics for all processed files."""
    summary = utils.format_summary(
        "remove_comments", stats_list, utils.REMOVE_COMMENTS_SUMMARY_ORDER
    )
    logger.info(summary)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        logger.error("Usage: python -m scripts.remove_comments INPUT OUTPUT")
        sys.exit(2)

    input_path_arg = sys.argv[1]
    output_path_arg = sys.argv[2]

    try:
        stats = transform(input_path_arg, output_path_arg)
        _print_summary(stats)
    except Exception as exc:
        logger.exception("ERROR in remove_comments: %s", exc)
        sys.exit(1)
