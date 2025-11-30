#!/usr/bin/env python3
"""
pipeline.py

Full DNS blocklist build pipeline for AdGuard Home.

Pipeline stages:
  1. remove_comments     — Strip comments and blank lines.
  2. validate            — Validate AdGuard-compatible syntax and hosts.
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
import time
from pathlib import Path
from typing import Any

import scripts.merge_and_classify as merge_and_classify
import scripts.remove_comments as remove_comments
import scripts.validate as validate


# ----------------------------------------
# Helpers
# ----------------------------------------
def run_stage(module, inp: Path, out: Path, label: str) -> dict[str, Any]:
    """Run a single pipeline stage (inp → out) with consistent console output."""
    print(f"\n[Pipeline] === {label} ===")
    start = time.perf_counter()
    stats = module.transform(str(inp), str(out))
    if hasattr(module, "_print_summary"):
        module._print_summary(stats)
    elapsed = time.perf_counter() - start
    print(f"[Pipeline] Finished {label} in {elapsed:.2f}s")
    return stats


# ----------------------------------------
# Pipeline core
# ----------------------------------------
def transform(input_dir: str, output_file: str) -> None:
    """Run the full blocklist processing pipeline."""

    run_start = time.perf_counter()
    inp_path = Path(input_dir)
    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    print("[Pipeline] Starting pipeline run")

    with tempfile.TemporaryDirectory(prefix="pipeline_") as tmpdir:
        tmp = Path(tmpdir)
        cleaned_dir = tmp / "cleaned"
        validated_dir = tmp / "validated"

        run_stage(remove_comments, inp_path, cleaned_dir, "Cleaning input files")
        run_stage(validate, cleaned_dir, validated_dir, "Validating rules")

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
        total_elapsed = time.perf_counter() - run_start
        print(f"[Pipeline] Output saved to: {out_path} (total {total_elapsed:.2f}s)")


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
