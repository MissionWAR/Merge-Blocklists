#!/usr/bin/env python3
"""
merge_and_classify.py

Merge, deduplicate, and classify rules for AdGuard Home (DNS-level blocking).

Usage:
    python -m scripts.merge_and_classify <input_dir> <merged_out>
"""
from __future__ import annotations

import ipaddress
import sys
import tempfile
from pathlib import Path

from typing import Iterator

from scripts import utils


# ----------------------------------------
# Import constants and helpers from utils (avoid duplication)
# ----------------------------------------
DOMAIN_PREFIX = utils.DOMAIN_PREFIX
DOMAIN_SEPARATOR = utils.DOMAIN_SEPARATOR
IO_BUFFER_SIZE = utils.IO_BUFFER_SIZE
substring_between = utils.substring_between
normalize_domain_token = utils.normalize_domain_token
walk_suffixes = utils.walk_suffixes


def has_parent(domain: str, domain_set: set[str]) -> bool:
    """Return True if any strict parent of domain exists in domain_set (fast, no allocations)."""
    if not domain:
        return False
    idx = domain.find(".")
    while idx != -1:
        domain = domain[idx + 1 :]
        if domain in domain_set:
            return True
        idx = domain.find(".")
    return False


def minimal_covering_set(domains: set[str]) -> set[str]:
    """
    Return minimal covering set:
    e.g., {'a.b.c', 'b.c'} -> {'b.c'} (since parent covers child).
    Algorithm: sort by label count (ascending) and greedily add.
    """
    # sort: fewer dots first (shorter suffixes), tie-breaker by length
    ordered = sorted(domains, key=lambda d: (d.count("."), len(d)))
    minimal: set[str] = set()
    for d in ordered:
        if not has_parent(d, minimal):
            minimal.add(d)
    return minimal


# ----------------------------------------
# IP helpers
# ----------------------------------------
def _canonicalize_ip(ip_raw: str) -> tuple[str | None, bool, bool]:
    """
    Return (canonical_ip, is_unspecified, is_loopback).
    Handles zone IDs in IPv6 addresses.
    """
    # Use utils.canonicalize_ip for basic canonicalization, then add metadata
    canonical = utils.canonicalize_ip(ip_raw)
    if canonical is None:
        return None, False, False
    
    try:
        ip_obj = ipaddress.ip_address(canonical)
        return str(ip_obj), ip_obj.is_unspecified, ip_obj.is_loopback
    except Exception:
        return None, False, False


# ----------------------------------------
# ABP first-pass collection (optimized single-pass with caching)
# ----------------------------------------
def collect_abp_and_cache_lines(input_dir: str) -> tuple[dict[str, set[str]], dict[str, list[str]]]:
    """
    Single-pass file reading: collect ABP domains AND cache all lines for later processing.
    
    IMPORTANT: Wildcard patterns (||*.domain^) are excluded from the minimal covering set
    because they have different semantics than exact domain matches:
      - ||*.lol^ blocks third-level+ domains (sub.example.lol)
      - ||00oo.lol^ blocks second-level domain (00oo.lol)
    
    These are NOT redundant - they target different DNS hierarchy levels.
    
    Returns: (abp_sets, file_lines_cache)
      - abp_sets: {'raw_abp': set, 'abp_minimal': set}
      - file_lines_cache: {filename: [line1, line2, ...]}
    """
    raw_abp: set[str] = set()
    file_lines_cache: dict[str, list[str]] = {}
    input_path = Path(input_dir)
    
    for entry in sorted(input_path.iterdir(), key=lambda p: p.name.lower()):
        if not entry.name.lower().endswith(".txt"):
            continue
        if not entry.is_file():
            continue
        
        lines: list[str] = []
        with entry.open(encoding="utf-8-sig", errors="replace", buffering=IO_BUFFER_SIZE) as fh:
            for raw in fh:
                line = raw.rstrip("\r\n").strip()
                lines.append(line)
                
                if not line:
                    continue
                    
                # Collect ABP domains for minimal covering set
                dom = substring_between(line, DOMAIN_PREFIX, DOMAIN_SEPARATOR)
                if dom:
                    # Handle wildcard patterns:
                    # - ||*.lol^ (TLD wildcard) → treat as blocking all .lol domains
                    # - ||*.example.com^ (subdomain wildcard) → only blocks subdomains, not example.com itself
                    if dom.startswith("*."):
                        # Strip the wildcard prefix
                        base = dom[2:]
                        # If no dots remain, it's a TLD wildcard (e.g., *.lol → lol)
                        # These should participate in deduplication (||*.lol^ removes ||example.lol^)
                        if "." not in base:
                            dn_norm = normalize_domain_token(base)
                            if dn_norm:
                                raw_abp.add(dn_norm)
                        # If dots remain, it's a subdomain wildcard (e.g., *.example.com → example.com)
                        # Skip these - they don't block the parent domain itself
                        continue
                    
                    # Normal domain rules
                    dn_norm = normalize_domain_token(dom)
                    if dn_norm:
                        raw_abp.add(dn_norm)
        
        # Cache lines for later processing
        file_lines_cache[entry.name] = lines
    
    return ({"raw_abp": raw_abp, "abp_minimal": minimal_covering_set(raw_abp)}, file_lines_cache)


# ----------------------------------------
# Main merge/dedupe/classify
# ----------------------------------------
def transform(input_dir: str, merged_out: str) -> dict[str, int]:
    """Merge, dedupe, and classify rules. Write merged_out atomically."""
    in_path = Path(input_dir)
    if not in_path.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    # Single-pass: collect ABP sets and cache all file lines
    abp_sets, file_lines_cache = collect_abp_and_cache_lines(input_dir)
    abp_minimal = abp_sets["abp_minimal"]

    # domain_map: domain_norm -> (type, text, ip)
    domain_map: dict[str, tuple[str, str, str | None]] = {}
    host_line_to_hostnames: dict[str, list[str]] = {}
    host_line_to_hostnames_norm: dict[str, set[str]] = {}
    host_line_to_ip: dict[str, str] = {}

    # Use an insertion-ordered dict for final rules so we can write without an expensive sort.
    final_rules: dict[str, None] = {}
    seen_rules_text: set[str] = set()

    stats = {
        "files": 0,
        "lines_in": 0,
        "lines_out": 0,
        "duplicates_removed": 0,
        "plain_or_hosts_removed_by_abp": 0,
        "abp_subdomains_removed": 0,
        "invalid_removed": 0,
        "conflicting_hosts_skipped": 0,
        "conflicting_hosts_replaced": 0,
    }

    # Local refs for speed on big lists
    normalize = normalize_domain_token
    domain_regex = utils.DOMAIN_REGEX
    is_hosts_re = utils.is_etc_hosts_rule
    load_hosts = utils.load_etc_hosts_rule_properties
    canonicalize_ip = _canonicalize_ip
    re_abp_bare = utils.ABP_HOSTNAME_RE

    # ------------------------------
    # Process cached file lines (no re-reading files)
    # ------------------------------
    for filename in sorted(file_lines_cache.keys(), key=lambda n: n.lower()):
        lines = file_lines_cache[filename]
        stats["files"] += 1
        
        for line in lines:
            stats["lines_in"] += 1
            if not line:
                continue

            # ----------------------------------------
            # 1. /etc/hosts-style rules
            # ----------------------------------------
            if is_hosts_re(line):
                try:
                    props = load_hosts(line)
                except Exception:
                    stats["invalid_removed"] += 1
                    continue

                ip_part = props["ip"]
                hostnames = props["hostnames"]
                hn_norm = [normalize(h) for h in hostnames]
                hn_norm_set = {h for h in hn_norm if h}

                # Drop if covered by ABP minimal (parent or exact)
                if any(
                    any(parent in abp_minimal for parent in walk_suffixes(h))
                    for h in hn_norm
                    if h
                ):
                    stats["plain_or_hosts_removed_by_abp"] += 1
                    continue

                out_line = f"{ip_part} {' '.join(hostnames)}"
                if out_line in seen_rules_text:
                    stats["duplicates_removed"] += 1
                    continue

                skip_line = False
                will_replace_prev_text: str | None = None

                for single_norm in hn_norm:
                    if not single_norm:
                        continue
                    if single_norm in domain_map:
                        prev_type, prev_text, prev_ip = domain_map[single_norm]
                        if prev_type == "abp":
                            # ABP rule dominates hosts in terms of coverage semantics here
                            skip_line = True
                            stats["plain_or_hosts_removed_by_abp"] += 1
                            break
                        if prev_type == "plain":
                            # hosts should replace plain domains -> remove the plain entry
                            if prev_text in final_rules:
                                final_rules.pop(prev_text, None)
                            seen_rules_text.discard(prev_text)
                            domain_map.pop(single_norm, None)
                            stats["duplicates_removed"] += 1
                            continue
                        if prev_type == "hosts":
                            # identical hostname set?
                            prev_norm_set = host_line_to_hostnames_norm.get(
                                prev_text
                            )
                            if prev_norm_set == hn_norm_set:
                                prev_ip_raw = host_line_to_ip.get(prev_text, "")
                                prev_ip_canon, prev_unspec, prev_loopback = (
                                    canonicalize_ip(prev_ip_raw)
                                )
                                new_ip_canon, new_unspec, new_loopback = (
                                    canonicalize_ip(ip_part)
                                )

                                # If canonical IPs are equal -> duplicate hosts line
                                if (
                                    prev_ip_canon
                                    and new_ip_canon
                                    and prev_ip_canon == new_ip_canon
                                ):
                                    skip_line = True
                                    stats["duplicates_removed"] += 1
                                    break

                                # If previous is unspecified (0.0.0.0/::) and new is loopback, prefer loopback
                                if prev_unspec and new_loopback:
                                    will_replace_prev_text = prev_text
                                    break
                                # otherwise treat as conflict and skip
                                skip_line = True
                                break
                            else:
                                # different sets of hostnames for same normalized hostname -> skip
                                skip_line = True
                                break
                        else:
                            skip_line = True
                            break

                if skip_line:
                    stats["conflicting_hosts_skipped"] += 1
                    continue

                if will_replace_prev_text:
                    prev_text = will_replace_prev_text
                    prev_hostnames = host_line_to_hostnames.get(prev_text, [])
                    # remove previous host mapping
                    final_rules.pop(prev_text, None)
                    seen_rules_text.discard(prev_text)
                    for ph in prev_hostnames:
                        ph_norm = normalize(ph)
                        cur = domain_map.get(ph_norm)
                        if cur and cur[1] == prev_text:
                            domain_map.pop(ph_norm, None)
                    stats["conflicting_hosts_replaced"] += 1

                # Add new hosts mapping
                seen_rules_text.add(out_line)
                final_rules[out_line] = None
                host_line_to_hostnames[out_line] = list(hostnames)
                host_line_to_hostnames_norm[out_line] = hn_norm_set
                host_line_to_ip[out_line] = ip_part
                for single_norm in hn_norm:
                    if single_norm:
                        domain_map[single_norm] = ("hosts", out_line, ip_part)
                stats["lines_out"] += 1
                continue

            # ----------------------------------------
            # 2. ABP rule (||domain^)
            # ----------------------------------------
            abp_domain = substring_between(line, DOMAIN_PREFIX, DOMAIN_SEPARATOR)
            if abp_domain:
                # For wildcard subdomain patterns (||*.example.com^), preserve the wildcard in the map key
                # to avoid collision with parent domain rules (||example.com^)
                is_wildcard_subdomain = abp_domain.startswith("*.") and "." in abp_domain[2:]
                
                dn_norm = normalize(abp_domain)
                if not dn_norm:
                    stats["invalid_removed"] += 1
                    continue

                # If a parent ABP already covers this domain, remove this subdomain
                # ONLY if this line is a bare ABP rule (no options) and not a whitelist.
                if has_parent(dn_norm, abp_minimal):
                    if not line.startswith("@@") and re_abp_bare.match(line):
                        stats["abp_subdomains_removed"] += 1
                        continue
                    # otherwise keep the more-specific rule (it might carry modifiers)

                # Determine the key for domain_map
                # Wildcard subdomain patterns use "*.{normalized}" to avoid collision with parent
                map_key = f"*.{dn_norm}" if is_wildcard_subdomain else dn_norm

                # Check if this normalized domain already exists as an ABP rule
                # This catches case variations (||Example.COM^ vs ||example.com^)
                # and trailing dot differences (||example.com.^ vs ||example.com^)
                # BUT only if both rules are bare (no modifiers) - rules with modifiers must be kept
                if map_key in domain_map:
                    prev_type, prev_text, _ = domain_map[map_key]
                    if prev_type == "abp":
                        # Only deduplicate if BOTH current and previous are bare ABP rules
                        # (rules with modifiers like $important must be kept even if domain matches)
                        # Note: Wildcard subdomains (||*.example.com^) are treated as bare rules
                        current_is_bare = re_abp_bare.match(line) or (is_wildcard_subdomain and "$" not in line)
                        prev_is_bare = re_abp_bare.match(prev_text) or ("*." in prev_text and "$" not in prev_text)
                        if current_is_bare and prev_is_bare:
                            # Both are bare rules, safe to deduplicate
                            stats["duplicates_removed"] += 1
                            continue
                        # else: at least one has modifiers, keep both

                # Also check exact rule text (safety check for perfect duplicates)
                if line in seen_rules_text:
                    stats["duplicates_removed"] += 1
                    continue

                seen_rules_text.add(line)
                final_rules[line] = None
                domain_map[map_key] = ("abp", line, None)
                stats["lines_out"] += 1
                continue

            # ----------------------------------------
            # 3. Plain domains (example.com)
            # ----------------------------------------
            if "." in line and domain_regex.match(line):
                dn = normalize(line)
                if not dn:
                    stats["invalid_removed"] += 1
                    continue

                # If ABP covers this domain (exact or parent), drop the plain domain.
                # walk_suffixes yields domain and all parents, so single check is sufficient.
                if any(parent in abp_minimal for parent in walk_suffixes(dn)):
                    stats["plain_or_hosts_removed_by_abp"] += 1
                    continue

                # If a hosts mapping already claims this domain, prefer hosts and skip the plain domain.
                # Also catches if plain domain already seen (avoiding redundant check below)
                dm = domain_map.get(dn)
                if dm:
                    if dm[0] == "hosts":
                        stats["plain_or_hosts_removed_by_abp"] += 1
                    else:
                        stats["duplicates_removed"] += 1
                    continue
                if line in seen_rules_text:
                    stats["duplicates_removed"] += 1
                    continue

                seen_rules_text.add(line)
                final_rules[line] = None
                domain_map[dn] = ("plain", line, None)
                stats["lines_out"] += 1
                continue

            # ----------------------------------------
            # 4. Everything else (regex, fragments, etc.)
            #    We keep these as-is; aggressive filtering is responsibility of validate.py
            # ----------------------------------------
            if line in seen_rules_text:
                stats["duplicates_removed"] += 1
                continue
            seen_rules_text.add(line)
            final_rules[line] = None
            stats["lines_out"] += 1

    # ----------------------------------------
    # Atomic write output (write in insertion order, avoid global sort)
    # ----------------------------------------
    out_path = Path(merged_out)
    out_dir = out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write main blocklist
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=out_dir,
            prefix=".tmp_merged_",
            delete=False,
            buffering=IO_BUFFER_SIZE,  # 128KB buffer optimized for modern SSDs
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            # write rules in insertion order (no costly sort on very large sets)
            for r in final_rules:
                tmp_file.write(r + "\n")
            tmp_file.flush()
        tmp_path.replace(out_path)
        tmp_path = None
    finally:
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass

    return stats


# ----------------------------------------
# Summary printer
# ----------------------------------------
def _print_summary(stats: dict[str, int]) -> None:
    print(
        "merge_and_classify: "
        f"files={stats.get('files', 0)} lines_in={stats.get('lines_in', 0)} "
        f"lines_out={stats.get('lines_out', 0)} duplicates_removed={stats.get('duplicates_removed', 0)} "
        f"plain_or_hosts_removed_by_abp={stats.get('plain_or_hosts_removed_by_abp', 0)} "
        f"abp_subdomains_removed={stats.get('abp_subdomains_removed', 0)} "
        f"invalid_removed={stats.get('invalid_removed', 0)} "
        f"conflicting_hosts_replaced={stats.get('conflicting_hosts_replaced', 0)} "
        f"conflicting_hosts_skipped={stats.get('conflicting_hosts_skipped', 0)}"
    )


# ----------------------------------------
# CLI entrypoint
# ----------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(
            "Usage: python -m scripts.merge_and_classify <input_dir> <merged_out>",
            file=sys.stderr,
        )
        sys.exit(2)
    inp = sys.argv[1]
    merged = sys.argv[2]
    try:
        stats = transform(inp, merged)
        _print_summary(stats)
    except Exception as exc:
        print(f"ERROR in merge_and_classify: {exc}", file=sys.stderr)
        sys.exit(1)
