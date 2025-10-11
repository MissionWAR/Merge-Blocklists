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
    """
    Run a pipeline stage module on (inp → out).

    Each module must implement a `transform()` function.
    Optionally, a `_print_summary()` function can be used for logging.
    """
    print(f">>> Stage: {label}")
    stats = module.transform(str(inp), str(out))
    if hasattr(module, "_print_summary"):
        try:
            module._print_summary(stats)
        except Exception as exc:
            print(f"[WARN] Failed to print summary for {label}: {exc}")
    return stats


# ----------------------------------------
# Pipeline core
# ----------------------------------------
def transform(input_dir: str, output_file: str) -> None:
    """
    Execute the full AdGuard DNS blocklist build pipeline.

    Steps:
        input_dir
            → remove_comments
            → validate
            → merge_and_classify
            → output_file (atomic move)
    """
    inp_path = Path(input_dir)
    out_path = Path(output_file)

    if not inp_path.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    with tempfile.TemporaryDirectory(prefix="pipeline_") as tmpdir:
        tmp_root = Path(tmpdir)
        stage_remove = tmp_root / "remove"
        stage_validate = tmp_root / "validate"
        merged_tmp = tmp_root / "merged.txt"

        # Stage 1: Remove comments and empty lines
        run_stage(remove_comments, inp_path, stage_remove, "remove_comments")

        # Stage 2: Validate AdGuard-compatible rules
        run_stage(
            validate, stage_remove, stage_validate, "validate"
        )

        # Stage 3: Merge and deduplicate
        stats = merge_and_classify.transform(str(stage_validate), str(merged_tmp))
        if hasattr(merge_and_classify, "_print_summary"):
            merge_and_classify._print_summary(stats)

        # Ensure destination directory exists
        out_path.parent.mkdir(parents=True, exist_ok=True)

        # Atomic move to final location
        tmp_final = out_path.with_suffix(out_path.suffix + ".tmp")
        try:
            shutil.move(str(merged_tmp), str(tmp_final))
            tmp_final.replace(out_path)
        except Exception as exc:
            # Clean up tmp_final if it was created but replace failed
            if tmp_final.exists():
                try:
                    tmp_final.unlink(missing_ok=True)
                except Exception:
                    pass
            print(f"[ERROR] Failed to finalize output: {exc}", file=sys.stderr)
            raise

        print(f">>> Pipeline complete. Final merged file: {out_path}")


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
