#!/usr/bin/env python3
"""
pipeline.py

Full DNS blocklist build pipeline for AdGuard Home with cache-aware cleanup/validation.

Pipeline stages:
  1. remove_comments     — Strip comments and blank lines (reuses cached outputs when possible).
  2. validate            — Validate AdGuard-compatible syntax and hosts (cache-aware).
  3. merge_and_classify  — Merge, deduplicate, and normalize into a single output.

Each stage writes to a temporary directory and passes its result to the next.
The final merged output is atomically moved to the destination file.

Usage:
    python -m scripts.pipeline <input_dir> <output_file>
"""

from __future__ import annotations

import os
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

import scripts.merge_and_classify as merge_and_classify
import scripts.remove_comments as remove_comments
import scripts.validate as validate
from scripts import utils
from scripts.cache_utils import IntermediateResultCache


INTERMEDIATE_CACHE_DIR_NAME = ".pipeline_cache"


# ----------------------------------------
# Helpers
# ----------------------------------------
def run_stage(module, inp: Path, out: Path, label: str) -> dict[str, Any]:
    """Run a single pipeline stage (inp → out).
    
    Each stage module must have a transform() function that takes input and output paths.
    If the module has a _print_summary() function, it will be called with the stats.
    """
    print(f"[Pipeline] Starting stage: {label}")
    stats = module.transform(str(inp), str(out))
    if hasattr(module, "_print_summary"):
        module._print_summary(stats)
    return stats


def _collect_source_files(inp: Path) -> list[Path]:
    """Return alphabetized list of source .txt files for the pipeline."""
    return utils.list_text_rule_files(inp)


def _cache_dir_for_input(inp: Path) -> Path:
    return inp / INTERMEDIATE_CACHE_DIR_NAME


def _process_clean_validate_job(args: tuple[str, str, str]) -> tuple[dict[str, int | str], dict[str, int | str]]:
    """Worker to run remove_comments + validate for a single file."""
    src, cleaned_dest, validated_dest = args
    clean_result = remove_comments.process_file(src, cleaned_dest)
    validate_result = validate.process_file(cleaned_dest, validated_dest)
    return clean_result, validate_result


def _clean_and_validate_with_cache(
    files: list[Path],
    inp_root: Path,
    cleaned_dir: Path,
    validated_dir: Path,
    cache: IntermediateResultCache,
) -> tuple[list[dict[str, int | str]], list[dict[str, int | str]], int]:
    """
    Clean + validate inputs while persisting intermediates (cache-aware by design).

    Returns per-stage stats along with a reuse counter indicating how many files
    were restored directly from the intermediate cache (those files skip re-run).
    """
    clean_stats: list[dict[str, int | str]] = []
    validate_stats: list[dict[str, int | str]] = []
    reused = 0

    cleaned_dir.mkdir(parents=True, exist_ok=True)
    validated_dir.mkdir(parents=True, exist_ok=True)

    jobs: list[tuple[str, str, str]] = []
    job_meta: list[tuple[str, str, Path, Path]] = []

    for src in files:
        rel_path = src.relative_to(inp_root)
        rel_key = rel_path.as_posix()
        raw_hash = cache.raw_hash(src)
        cleaned_dest = cleaned_dir / rel_path
        validated_dest = validated_dir / rel_path

        if cache.can_reuse(rel_key, raw_hash) and cache.restore(
            rel_key, cleaned_dest, validated_dest
        ):
            reused += 1
            continue

        jobs.append((str(src), str(cleaned_dest), str(validated_dest)))
        job_meta.append((rel_key, raw_hash, cleaned_dest, validated_dest))

    if jobs:
        max_workers = min(os.cpu_count() or 1, len(jobs))
        if len(jobs) == 1:
            clean_result, validate_result = _process_clean_validate_job(jobs[0])
            clean_stats.append(clean_result)
            validate_stats.append(validate_result)
            rel_key, raw_hash, cleaned_dest, validated_dest = job_meta[0]
            try:
                cache.store_result(rel_key, raw_hash, cleaned_dest, validated_dest)
            except Exception as exc:
                print(
                    f"[Pipeline] Warning: failed to cache intermediates for {rel_key}: {exc}",
                    file=sys.stderr,
                )
        else:
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                for (clean_result, validate_result), meta in zip(
                    executor.map(_process_clean_validate_job, jobs), job_meta
                ):
                    clean_stats.append(clean_result)
                    validate_stats.append(validate_result)
                    rel_key, raw_hash, cleaned_dest, validated_dest = meta
                    try:
                        cache.store_result(rel_key, raw_hash, cleaned_dest, validated_dest)
                    except Exception as exc:
                        print(
                            f"[Pipeline] Warning: failed to cache intermediates for {rel_key}: {exc}",
                            file=sys.stderr,
                        )

    return clean_stats, validate_stats, reused


# ----------------------------------------
# Pipeline core
# ----------------------------------------
def transform(input_dir: str, output_file: str) -> None:
    """Run the full blocklist processing pipeline."""

    inp_path = Path(input_dir)
    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    source_files = _collect_source_files(inp_path)
    cache_dir = _cache_dir_for_input(inp_path)
    cache = IntermediateResultCache(cache_dir)

    with tempfile.TemporaryDirectory(prefix="pipeline_") as tmpdir:
        tmp = Path(tmpdir)
        cleaned_dir = tmp / "cleaned"
        validated_dir = tmp / "validated"

        print("[Pipeline] Starting stage: Cleaning input files")
        clean_stats, validate_stats, reused = _clean_and_validate_with_cache(
            source_files, inp_path, cleaned_dir, validated_dir, cache
        )
        if hasattr(remove_comments, "_print_summary"):
            remove_comments._print_summary(clean_stats)

        print("[Pipeline] Starting stage: Validating rules")
        if hasattr(validate, "_print_summary"):
            validate._print_summary(validate_stats)

        total_files = len(source_files)
        if total_files:
            print(
                f"[Pipeline] Cached intermediates reused: {reused}/{total_files} files"
            )

        merge_parent = out_path.parent
        fd, merge_name = tempfile.mkstemp(
            prefix=".tmp_pipeline_", suffix=".txt", dir=merge_parent
        )
        os.close(fd)
        merge_target = Path(merge_name)
        try:
            merge_target.unlink(missing_ok=True)
        except Exception:
            pass

        run_stage(
            merge_and_classify,
            validated_dir,
            merge_target,
            "Merging and deduplicating",
        )

        merge_target.replace(out_path)
        print(f"[Pipeline] Successfully saved output to: {out_path}")


# CLI entrypoint
# ----------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m scripts.pipeline <input_dir> <output_file>")
        sys.exit(2)

    inp = sys.argv[1]
    out = sys.argv[2]

    try:
        transform(inp, out)
    except Exception as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        sys.exit(1)
