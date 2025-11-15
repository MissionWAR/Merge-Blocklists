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

import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import scripts.merge_and_classify as merge_and_classify
import scripts.remove_comments as remove_comments
import scripts.validate as validate


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


# ----------------------------------------
# Pipeline core
# ----------------------------------------
def transform(input_dir: str, output_file: str) -> None:
    """Run the full blocklist processing pipeline.
    
    Processing steps:
    1. Remove comments and empty lines
    2. Validate rules
    3. Merge and deduplicate
    4. Save final output
    """
    inp_path = Path(input_dir)
    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    
    with tempfile.TemporaryDirectory(prefix="pipeline_") as tmpdir:
        tmp = Path(tmpdir)
        
        # Stage 1: Clean up input files
        cleaned_dir = tmp / "cleaned"
        run_stage(remove_comments, inp_path, cleaned_dir, "Cleaning input files")
        
        # Stage 2: Validate rules
        validated_dir = tmp / "validated"
        run_stage(validate, cleaned_dir, validated_dir, "Validating rules")
        
        # Stage 3: Merge and deduplicate
        merged_file = tmp / "merged.txt"
        run_stage(merge_and_classify, validated_dir, merged_file, "Merging and deduplicating")
        
        # Save final output atomically
        merged_file.replace(out_path)
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
