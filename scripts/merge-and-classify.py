#!/usr/bin/env python3
"""
scripts/merge-and-classify.py

Hosts-first merge and dedupe with optional Public Suffix List (PSL) support.

Behavior (unchanged):
- Hosts-format entries (e.g. "0.0.0.0 example.org") are canonical and preferred.
- If a domain appears as a hosts entry, ABP/wildcard or plain-domain rules that
  would otherwise cover the same registrable domain (eTLD+1) are considered
  covered and dropped.
- Output preserves first-seen ordering and removes duplicates.

PSL support:
- If `tldextract` is available, this script uses a packaged PSL snapshot (no network fetch)
  to compute registrable domains (eTLD+1), which is more correct than naive "last-two-labels".
- Use `--no-psl` to force the naive behavior even if tldextract is installed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# ----------------------------
# Regexes for common rule types
# ----------------------------
RE_COMMENT = re.compile(r"^\s*[#!]")  # lines starting with # or !
RE_HOSTS = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::)\s+([^\s#]+)", re.I)  # hosts file style
RE_ABP_WILDCARD = re.compile(r"^\s*\|\|([^\^\/\s]+)", re.I)  # adblock "||domain^"
RE_PLAIN_DOMAIN = re.compile(r"^\s*([a-z0-9\-.]+\.[a-z]{2,})\s*$", re.I)  # domain.tld

# ----------------------------
# PSL / domain helpers
# ----------------------------
def normalize_domain(domain: str) -> str:
    """Lowercase, trim and remove trailing dot."""
    return domain.strip().lower().rstrip(".")


def _naive_base_domain(domain: str) -> str:
    """Naive last-two-labels fallback (fast but inaccurate on multi-part TLDs)."""
    d = normalize_domain(domain)
    parts = d.split(".")
    if len(parts) <= 2:
        return d
    return ".".join(parts[-2:])


# prepare a tldextract extractor if available (no remote fetch)
_TLD_EXTRACTOR = None
try:
    import tldextract  # type: ignore

    try:
        _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)
    except Exception:
        _TLD_EXTRACTOR = None
except Exception:
    _TLD_EXTRACTOR = None

# runtime flag to allow disabling PSL even when tldextract is present
_USE_PSL = _TLD_EXTRACTOR is not None


def base_domain(domain: str) -> str:
    """
    Return the registrable base domain (eTLD+1) for `domain`.

    Uses tldextract if available (and not explicitly disabled), otherwise falls back
    to the naive last-two-label heuristic.
    """
    d = normalize_domain(domain)
    if not d:
        return d
    if _USE_PSL and _TLD_EXTRACTOR is not None:
        try:
            ext = _TLD_EXTRACTOR(d)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
        except Exception:
            # fallback if tldextract misbehaves
            pass
    return _naive_base_domain(d)


# ----------------------------
# Parsing & dedupe utilities
# ----------------------------
def parse_rule(line: str) -> Tuple[str, Optional[str]]:
    """
    Classify a single input line.

    Returns (kind, key)
      kind in {"hosts", "abp", "domain", "other", "comment", "empty"}
      key is normalized domain for hosts/abp/domain kinds, otherwise None.
    """
    s = line.strip()
    if not s:
        return "empty", None
    if RE_COMMENT.match(s):
        return "comment", None
    m = RE_HOSTS.match(s)
    if m:
        return "hosts", normalize_domain(m.group(1))
    m = RE_ABP_WILDCARD.match(s)
    if m:
        return "abp", normalize_domain(m.group(1))
    m = RE_PLAIN_DOMAIN.match(s)
    if m:
        return "domain", normalize_domain(m.group(1))
    return "other", None


def dedupe_preserve_order(lines: Iterable[str]) -> List[str]:
    """Return lines with duplicates removed while preserving first-seen order."""
    seen = set()
    out: List[str] = []
    for ln in lines:
        key = ln.strip()
        if not key:
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(ln)
    return out


# ----------------------------
# Core merge logic (hosts-first)
# ----------------------------
def merge_and_prioritize(raw_lines: Iterable[str]) -> Tuple[List[str], Dict]:
    """
    Merge input lines into a canonical hosts-first list.

    Returns (kept_lines, stats).
    """
    raw = list(raw_lines)
    total_non_comment = len([r for r in raw if r.strip() and not RE_COMMENT.match(r)])

    hosts_list: List[Tuple[str, str]] = []
    domain_list: List[Tuple[str, str]] = []
    abp_list: List[Tuple[str, str]] = []
    other_list: List[str] = []

    for line in raw:
        kind, key = parse_rule(line)
        if kind == "hosts" and key:
            hosts_list.append((line.rstrip("\n"), key))
        elif kind == "domain" and key:
            domain_list.append((line.rstrip("\n"), key))
        elif kind == "abp" and key:
            abp_list.append((line.rstrip("\n"), key))
        elif kind in ("comment", "empty"):
            continue
        else:
            other_list.append(line.rstrip("\n"))

    # Hosts are canonical and come first
    kept: List[str] = [r for r, _ in hosts_list]
    kept_base_domains = {base_domain(dom) for _, dom in hosts_list}

    dropped = []

    for line, dom in domain_list:
        if base_domain(dom) in kept_base_domains:
            dropped.append({"line": line, "reason": "covered_by_hosts", "domain": dom})
            continue
        kept.append(line)

    for line, dom in abp_list:
        if base_domain(dom) in kept_base_domains:
            dropped.append({"line": line, "reason": "abp_covered_by_hosts", "abp_domain": dom})
            continue
        kept.append(line)

    kept.extend(other_list)
    final_kept = dedupe_preserve_order(kept)

    stats = {
        "total_raw_rules_non_comment": total_non_comment,
        "total_hosts_rules": len(hosts_list),
        "total_domain_rules": len(domain_list),
        "total_abp_rules": len(abp_list),
        "total_other_rules": len(other_list),
        "kept_rules": len(final_kept),
        "dropped_rules": len(dropped),
        "dropped_examples": dropped[:50],
        "psl_enabled": _USE_PSL and (_TLD_EXTRACTOR is not None),
    }
    return final_kept, stats


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Merge and prioritize blocklist rules (hosts-first canonical).")
    ap.add_argument("--raw", required=True, help="Input concatenated raw file (e.g. output/_raw.txt)")
    ap.add_argument("--out", required=True, help="Output merged file (e.g. output/merged.txt)")
    ap.add_argument("--stats", default=None, help="JSON stats output path (default: <out>.stats.json)")
    ap.add_argument("--no-psl", action="store_true", help="Disable PSL/tldextract even if available (use naive last-two-labels)")
    ap.add_argument("--verbose", action="store_true", help="Enable debug logging (not heavy)")

    args = ap.parse_args(argv)

    # allow runtime override of PSL usage
    global _USE_PSL
    if args.no_psl:
        _USE_PSL = False

    if args.verbose:
        # lightweight logging: print whether PSL is active
        print(f"PSL enabled: {_USE_PSL and (_TLD_EXTRACTOR is not None)}")

    raw_path = Path(args.raw)
    if not raw_path.exists():
        print(f"ERROR: raw file not found: {raw_path}", file=sys.stderr)
        return 2

    raw_lines = raw_path.read_text(encoding="utf-8", errors="replace").splitlines()
    kept_lines, stats = merge_and_prioritize(raw_lines)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_text = "\n".join(kept_lines).rstrip() + "\n"
    out_path.write_text(out_text, encoding="utf-8")

    stats_path = Path(args.stats) if args.stats else out_path.with_suffix(out_path.suffix + ".stats.json")
    stats_path.write_text(json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"WROTE: {out_path}  (kept: {stats['kept_rules']}, dropped: {stats['dropped_rules']})")
    print(f"WROTE: {stats_path}  (psl_enabled={stats.get('psl_enabled')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
