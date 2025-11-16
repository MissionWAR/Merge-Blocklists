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
from dataclasses import dataclass, field
from pathlib import Path

from typing import Callable, Pattern

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
has_parent = utils.has_parent_domain
minimal_covering_set = utils.minimal_covering_set
is_domain_covered_by_wildcard = utils.is_domain_covered_by_wildcard
build_plain_domain_minimal_set = utils.build_plain_domain_minimal_set


def _is_bare_abp_rule(
    rule_text: str, is_wildcard_subdomain: bool, re_abp_bare: Pattern[str]
) -> bool:
    """Return True if the ABP rule has no modifiers (pure blocking)."""
    if re_abp_bare.match(rule_text):
        return True
    return is_wildcard_subdomain and "$" not in rule_text


def _abp_rule_is_redundant(
    domain_norm: str,
    *,
    is_bare_rule: bool,
    is_whitelist_rule: bool,
    ctx: MergeContext,
) -> bool:
    """
    Return True if a bare blocking rule is already enforced by a broader rule.

    A rule is redundant when:
      * a parent domain is present in the ABP minimal set, e.g. '||example.com^'
        already covers '||a.example.com^'; or
      * the domain falls under a wildcard (||*.example.com^).
    """
    if is_whitelist_rule or not is_bare_rule or not domain_norm:
        return False
    # Parent coverage: `has_parent` only succeeds for strict parents (not the domain itself)
    if has_parent(domain_norm, ctx.abp_minimal):
        return True
    # Wildcard coverage: honours that '*.example.com' does not cover the apex domain
    return is_domain_covered_by_wildcard(domain_norm, ctx.abp_wildcards)


def handle_hosts_line(
    line: str, state: MergeState, ctx: MergeContext, stats: dict[str, int]
) -> bool:
    """Process a /etc/hosts-style rule."""
    try:
        props = ctx.load_hosts_rule(line)
    except Exception:
        stats["invalid_removed"] += 1
        return True

    ip_part = props["ip"]
    hostnames = props["hostnames"]
    hn_norm = [ctx.normalize(h) for h in hostnames]
    hn_norm_set = {h for h in hn_norm if h}

    if any(ctx.covered_by_abp(h) for h in hn_norm_set):
        stats["hosts_removed_by_abp"] += 1
        return True

    out_line = f"{ip_part} {' '.join(hostnames)}"
    if state.has_seen(out_line):
        stats["duplicates_removed"] += 1
        return True

    skip_line = False
    will_replace_prev_text: str | None = None

    for single_norm in hn_norm:
        if not single_norm:
            continue
        prev_entry = state.domain_map.get(single_norm)
        if not prev_entry:
            continue
        prev_type, prev_text, prev_ip = prev_entry
        if prev_type == "abp":
            skip_line = True
            stats["hosts_removed_by_abp"] += 1
            break
        if prev_type == "plain":
            state.remove_rule(prev_text)
            state.domain_map.pop(single_norm, None)
            stats["duplicates_removed"] += 1
            continue
        if prev_type == "hosts":
            prev_norm_set = state.host_line_to_hostnames_norm.get(prev_text)
            if prev_norm_set == hn_norm_set:
                prev_ip_raw = state.host_line_to_ip.get(prev_text, "")
                prev_ip_canon, prev_unspec, prev_loopback = ctx.canonicalize_ip(
                    prev_ip_raw
                )
                new_ip_canon, new_unspec, new_loopback = ctx.canonicalize_ip(ip_part)
                if (
                    prev_ip_canon
                    and new_ip_canon
                    and prev_ip_canon == new_ip_canon
                ):
                    skip_line = True
                    stats["duplicates_removed"] += 1
                    break
                if prev_unspec and new_loopback:
                    will_replace_prev_text = prev_text
                    break
                skip_line = True
                break
            skip_line = True
            break
        else:
            skip_line = True
            break

    if skip_line:
        stats["conflicting_hosts_skipped"] += 1
        return True

    if will_replace_prev_text:
        state.remove_host_entry(will_replace_prev_text, ctx.normalize)
        stats["conflicting_hosts_replaced"] += 1

    state.add_rule(out_line)
    state.host_line_to_hostnames[out_line] = list(hostnames)
    state.host_line_to_hostnames_norm[out_line] = hn_norm_set
    state.host_line_to_ip[out_line] = ip_part
    for single_norm in hn_norm:
        if single_norm:
            state.domain_map[single_norm] = ("hosts", out_line, ip_part)
    stats["lines_out"] += 1
    return True


def handle_abp_line(
    line: str,
    abp_domain: str,
    state: MergeState,
    ctx: MergeContext,
    stats: dict[str, int],
) -> bool:
    """Process an ABP-style rule."""
    is_whitelist_rule = line.startswith("@@")
    is_wildcard_subdomain = abp_domain.startswith("*.") and "." in abp_domain[2:]

    dn_norm = ctx.normalize(abp_domain)
    if not dn_norm:
        stats["invalid_removed"] += 1
        return True

    is_bare_rule = _is_bare_abp_rule(line, is_wildcard_subdomain, ctx.re_abp_bare)
    if _abp_rule_is_redundant(
        dn_norm,
        is_bare_rule=is_bare_rule,
        is_whitelist_rule=is_whitelist_rule,
        ctx=ctx,
    ):
        stats["abp_subdomains_removed"] += 1
        return True

    map_key = f"*.{dn_norm}" if is_wildcard_subdomain else dn_norm

    if is_whitelist_rule:
        state.whitelist_domains.add(map_key)
        stats["abp_whitelists_removed"] += 1
        prev = state.domain_map.get(map_key)
        if prev and prev[0] == "abp":
            state.remove_rule(prev[1])
            state.domain_map.pop(map_key, None)
            stats["abp_blocks_removed_by_whitelist"] += 1
        return True

    prev_entry = state.domain_map.get(map_key)
    if prev_entry and prev_entry[0] == "abp":
        prev_text = prev_entry[1]
        prev_is_wildcard = prev_text.startswith("||*.") and "." in prev_text[3:]
        prev_is_bare = _is_bare_abp_rule(
            prev_text, prev_is_wildcard, ctx.re_abp_bare
        )
        if is_bare_rule and prev_is_bare:
            stats["duplicates_removed"] += 1
            return True

    if state.has_seen(line):
        stats["duplicates_removed"] += 1
        return True

    if map_key in state.whitelist_domains:
        stats["abp_blocks_removed_by_whitelist"] += 1
        return True

    state.add_rule(line)
    state.domain_map[map_key] = ("abp", line, None)
    stats["lines_out"] += 1
    return True


def handle_plain_domain_line(
    line: str, state: MergeState, ctx: MergeContext, stats: dict[str, int]
) -> bool:
    """Process a plain domain (no ABP prefix or hosts IP)."""
    dn = ctx.normalize(line)
    if not dn:
        stats["invalid_removed"] += 1
        return True

    if ctx.covered_by_abp(dn):
        stats["plain_removed_by_abp"] += 1
        return True

    if has_parent(dn, ctx.plain_minimal):
        stats["plain_subdomains_removed"] += 1
        return True

    if dn in state.domain_map or state.has_seen(line):
        stats["duplicates_removed"] += 1
        return True

    state.add_rule(line)
    state.domain_map[dn] = ("plain", line, None)
    stats["lines_out"] += 1
    return True


def handle_other_line(line: str, state: MergeState, stats: dict[str, int]) -> None:
    """Process regex/fragments/other rules (no special handling)."""
    if state.has_seen(line):
        stats["duplicates_removed"] += 1
        return
    state.add_rule(line)
    stats["lines_out"] += 1


@dataclass
class MergeState:
    """
    Mutable state shared by the individual line handlers.

    Attributes:
        final_rules: Insertion-ordered mapping of every rule kept in the final list.
        seen_rules_text: Fast duplicate detector for raw rule text.
        domain_map: Maps normalized domains to a tuple(type, rule_text, ip).
        host_line_to_hostnames: Original hostnames for each hosts line.
        host_line_to_hostnames_norm: Normalized hostname set per hosts line.
        host_line_to_ip: Original IP (string) for each hosts line.
        whitelist_domains: Normalized domains removed due to whitelisting.
    """

    final_rules: dict[str, None] = field(default_factory=dict)
    seen_rules_text: set[str] = field(default_factory=set)
    domain_map: dict[str, tuple[str, str, str | None]] = field(default_factory=dict)
    host_line_to_hostnames: dict[str, list[str]] = field(default_factory=dict)
    host_line_to_hostnames_norm: dict[str, set[str]] = field(default_factory=dict)
    host_line_to_ip: dict[str, str] = field(default_factory=dict)
    whitelist_domains: set[str] = field(default_factory=set)

    def has_seen(self, text: str) -> bool:
        return text in self.seen_rules_text

    def add_rule(self, text: str) -> None:
        self.seen_rules_text.add(text)
        self.final_rules[text] = None

    def remove_rule(self, text: str) -> None:
        self.final_rules.pop(text, None)
        self.seen_rules_text.discard(text)

    def remove_host_entry(self, text: str, normalize: Callable[[str], str]) -> None:
        """Remove host-related bookkeeping for a hosts line that is being replaced."""
        hostnames = self.host_line_to_hostnames.pop(text, [])
        self.host_line_to_hostnames_norm.pop(text, None)
        self.host_line_to_ip.pop(text, None)
        self.remove_rule(text)
        for hostname in hostnames:
            norm = normalize(hostname)
            current = self.domain_map.get(norm)
            if current and current[1] == text:
                self.domain_map.pop(norm, None)


@dataclass(frozen=True)
class MergeContext:
    """
    Bundle of helpers and lookup sets shared by handlers.

    Attributes:
        normalize: Domain normalizer.
        load_hosts_rule: Parser for /etc/hosts lines.
        canonicalize_ip: Helper returning canonical IP + metadata.
        covered_by_abp: Predicate checking whether a plain domain is redundant.
        plain_minimal: Minimal covering set of plain domains from inputs.
        abp_minimal: Minimal covering set of ABP blocking domains.
        abp_wildcards: Bare domains extracted from wildcard ABP rules (||*.d^).
        re_abp_bare: Regex detecting bare blocking rules.
    """

    normalize: Callable[[str], str]
    load_hosts_rule: Callable[[str], dict]
    canonicalize_ip: Callable[[str], tuple[str | None, bool, bool]]
    covered_by_abp: Callable[[str], bool]
    plain_minimal: set[str]
    abp_minimal: set[str]
    abp_wildcards: set[str]
    re_abp_bare: Pattern[str]


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
    """Process input files once to collect ABP domains and cache stripped lines.
    
    Returns:
        tuple: (abp_sets, file_lines_cache)
            - abp_sets: {'raw_abp': set, 'abp_minimal': set, 'wildcard_roots': set}
            - file_lines_cache: {filename: [line1, line2, ...]} (lines already stripped)
    """
    raw_abp = set()
    wildcard_roots = set()
    file_lines_cache = {}
    
    # Process each .txt file in the input directory
    for file_path in Path(input_dir).glob('*.txt'):
        if not file_path.is_file():
            continue
            
        lines = []
        with file_path.open(encoding='utf-8-sig', errors='replace') as f:
            for line in f:
                line = line.strip()
                lines.append(line)
                
                if not line:
                    continue
                if line.startswith("@@"):
                    continue
                
                # Extract domain from ABP-style rules (||example.com^)
                domain = substring_between(line, DOMAIN_PREFIX, DOMAIN_SEPARATOR)
                if not domain:
                    continue
                
                # Handle wildcard patterns
                if domain.startswith('*.'):
                    base = domain[2:]
                    norm_base = normalize_domain_token(base)
                    if norm_base:
                        wildcard_roots.add(norm_base)
                    continue
                
                # Process regular domains
                norm_domain = normalize_domain_token(domain)
                if norm_domain:
                    raw_abp.add(norm_domain)
        
        # Cache the file contents for later processing
        file_lines_cache[file_path.name] = lines
    
    # Return both the raw domains and the minimal covering set
    return {
        'raw_abp': raw_abp,
        'abp_minimal': minimal_covering_set(raw_abp),
        'wildcard_roots': wildcard_roots,
    }, file_lines_cache


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
    abp_wildcards = abp_sets["wildcard_roots"]

    def _covered_by_abp(domain: str) -> bool:
        """Return True if a domain is covered by existing ABP root or wildcard rules."""
        if not domain:
            return False
        if any(parent in abp_minimal for parent in walk_suffixes(domain)):
            return True
        return is_domain_covered_by_wildcard(domain, abp_wildcards)

    stats = {
        "files": 0,
        "lines_in": 0,
        "lines_out": 0,
        "duplicates_removed": 0,
        "hosts_removed_by_abp": 0,
        "plain_removed_by_abp": 0,
        "abp_subdomains_removed": 0,
        "plain_subdomains_removed": 0,
        "invalid_removed": 0,
        "conflicting_hosts_skipped": 0,
        "conflicting_hosts_replaced": 0,
        "abp_whitelists_removed": 0,
        "abp_blocks_removed_by_whitelist": 0,
    }

    # Local refs for speed on big lists
    normalize = normalize_domain_token
    domain_regex = utils.DOMAIN_REGEX
    is_hosts_re = utils.is_etc_hosts_rule
    load_hosts = utils.load_etc_hosts_rule_properties
    canonicalize_ip = _canonicalize_ip
    re_abp_bare = utils.ABP_HOSTNAME_RE

    plain_minimal = build_plain_domain_minimal_set(
        file_lines_cache, normalize, domain_regex, is_hosts_re, _covered_by_abp
    )

    ctx = MergeContext(
        normalize=normalize,
        load_hosts_rule=load_hosts,
        canonicalize_ip=canonicalize_ip,
        covered_by_abp=_covered_by_abp,
        plain_minimal=plain_minimal,
        abp_minimal=abp_minimal,
        abp_wildcards=abp_wildcards,
        re_abp_bare=re_abp_bare,
    )
    state = MergeState()

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

            if is_hosts_re(line):
                handle_hosts_line(line, state, ctx, stats)
                continue

            abp_domain = substring_between(line, DOMAIN_PREFIX, DOMAIN_SEPARATOR)
            if abp_domain:
                handle_abp_line(line, abp_domain, state, ctx, stats)
                continue

            if "." in line and domain_regex.match(line):
                handle_plain_domain_line(line, state, ctx, stats)
                continue

            handle_other_line(line, state, stats)

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
            for r in state.final_rules:
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
        f"hosts_removed_by_abp={stats.get('hosts_removed_by_abp', 0)} "
        f"plain_removed_by_abp={stats.get('plain_removed_by_abp', 0)} "
        f"abp_subdomains_removed={stats.get('abp_subdomains_removed', 0)} "
        f"plain_subdomains_removed={stats.get('plain_subdomains_removed', 0)} "
        f"invalid_removed={stats.get('invalid_removed', 0)} "
        f"conflicting_hosts_replaced={stats.get('conflicting_hosts_replaced', 0)} "
        f"conflicting_hosts_skipped={stats.get('conflicting_hosts_skipped', 0)} "
        f"abp_whitelists_removed={stats.get('abp_whitelists_removed', 0)} "
        f"abp_blocks_removed_by_whitelist={stats.get('abp_blocks_removed_by_whitelist', 0)}"
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
