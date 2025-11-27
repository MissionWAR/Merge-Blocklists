# utils.py
"""
Utility functions for parsing and processing DNS blocklist rules.

This module provides core functionality for:
- Parsing AdBlock-style rules (||example.com^)
- Processing /etc/hosts format (0.0.0.0 example.com)
- Domain normalization and punycode conversion
- Comment detection and rule validation
- Escape character handling

Compatible with AdGuard Home DNS filtering syntax.
Aligns with AdGuard Hostlist Compiler semantics.

Example Usage:
    from scripts.utils import normalize_domain_token, load_adblock_rule_properties
    
    # Normalize domain for comparison
    domain = normalize_domain_token("Example.COM")  # Returns: "example.com"
    
    # Parse AdBlock rule
    props = load_adblock_rule_properties("||example.com^$important")
    # Returns: {"pattern": "||example.com^", "hostname": "example.com", ...}
    
    # Parse hosts rule
    props = load_etc_hosts_rule_properties("0.0.0.0 example.com")
    # Returns: {"ip": "0.0.0.0", "hostnames": ["example.com"]}
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import sys
from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Iterator, Sequence

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
logger = logging.getLogger(__name__)


# -------------------------
# Precompiled regexes & constants
# -------------------------

# AdGuard syntax constants (shared across scripts)
DOMAIN_PREFIX = "||"
DOMAIN_SEPARATOR = "^"
WILDCARD = "*"
ELEMENT_HIDING_MARKERS = ("##", "#@#", "#%#")

# Performance tuning constants
DOMAIN_CACHE_SIZE = 32768  # LRU cache size for domain normalization (~5M+ domains)
IO_BUFFER_SIZE = 131072  # 128KB buffer for file I/O (optimized for modern SSDs)

# Shared statistics key namespaces (avoid magic strings across modules)
REMOVE_COMMENTS_STATS_KEYS = SimpleNamespace(
    LINES_IN="lines_in",
    LINES_OUT="lines_out",
    TRIMMED="trimmed",
    DROPPED_COMMENTS="dropped_comments",
    DROPPED_EMPTY="dropped_empty",
)

VALIDATE_STATS_KEYS = SimpleNamespace(
    LINES_IN="lines_in",
    LINES_OUT="lines_out",
    REMOVED_INVALID="removed_invalid",
    REMOVED_ELEMENT_HIDING="removed_element_hiding",
    REMOVED_BAD_MODIFIER="removed_bad_modifier",
    REMOVED_INVALID_HOST="removed_invalid_host",
    REMOVED_MALFORMED="removed_malformed",
    KEPT_REGEX="kept_regex",
    KEPT_HOSTS="kept_hosts",
    KEPT_ADBLOCK_DOMAIN="kept_adblock_domain",
    KEPT_WILDCARD_TLD="kept_wildcard_tld",
    KEPT_OTHER_ADBLOCK="kept_other_adblock",
    REMOVED_COMMENTS="removed_comments",
    REMOVED_EMPTY="removed_empty",
)

REMOVE_COMMENTS_SUMMARY_ORDER = (
    REMOVE_COMMENTS_STATS_KEYS.LINES_IN,
    REMOVE_COMMENTS_STATS_KEYS.LINES_OUT,
    REMOVE_COMMENTS_STATS_KEYS.TRIMMED,
    REMOVE_COMMENTS_STATS_KEYS.DROPPED_COMMENTS,
    REMOVE_COMMENTS_STATS_KEYS.DROPPED_EMPTY,
)

VALIDATE_SUMMARY_ORDER = (
    VALIDATE_STATS_KEYS.LINES_IN,
    VALIDATE_STATS_KEYS.LINES_OUT,
    VALIDATE_STATS_KEYS.REMOVED_INVALID,
    VALIDATE_STATS_KEYS.REMOVED_ELEMENT_HIDING,
    VALIDATE_STATS_KEYS.REMOVED_BAD_MODIFIER,
    VALIDATE_STATS_KEYS.REMOVED_INVALID_HOST,
    VALIDATE_STATS_KEYS.REMOVED_COMMENTS,
    VALIDATE_STATS_KEYS.REMOVED_EMPTY,
)

_DOMAIN_REGEX = re.compile(
    r"^(?=.{1,255}$)[0-9A-Za-z]"
    r"(?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?"
    r"(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?$",
    flags=re.ASCII,
)

_ETC_HOSTS_REGEX = re.compile(
    r"^([0-9A-Fa-f:\.\[\]]+)(?:%[a-zA-Z0-9]+)?\s+([^#]+)(?:#.*)?$"
)
_DOMAIN_PATTERN_RE = re.compile(
    r"(\*\.)?([^\s\^$|=]+(?:\.[^\s\^$|=]+)+)", flags=re.UNICODE
)
_NON_ASCII_RE = re.compile(r"[^\x00-\x7F]")
_ABP_HOSTNAME_RE = re.compile(r"^\|\|([^\^]+)\^$", flags=re.IGNORECASE)
_COMMENT_SEPARATOR_RE = re.compile(r"^[-=*_\.]{3,}$")
_ELEMENT_HIDING_PATTERN_RE = re.compile(
    r"##|#@#|#%#"
)  # Optimized element-hiding marker pattern

# -------------------------
# Public regex pattern aliases (for shared use across scripts)
# -------------------------
DOMAIN_REGEX = _DOMAIN_REGEX
ETC_HOSTS_REGEX = _ETC_HOSTS_REGEX
ABP_HOSTNAME_RE = _ABP_HOSTNAME_RE
NON_ASCII_RE = _NON_ASCII_RE
ELEMENT_HIDING_PATTERN_RE = _ELEMENT_HIDING_PATTERN_RE  # Shared precompiled pattern


# -------------------------
# Basic helpers
# -------------------------


def is_blank_line(line: str | None) -> bool:
    """True if line is None or only whitespace."""
    return line is None or line.strip() == ""


def is_comment_line(line: str | None) -> bool:
    """Detect Adblock/Hostlist comments and separator lines."""
    if not line:
        return False
    s = line.lstrip()
    return s[:1] in ("!", "#") or _COMMENT_SEPARATOR_RE.fullmatch(s) is not None


def contains_non_ascii_characters(s: str) -> bool:
    """Return True if string contains non-ASCII characters."""
    if not isinstance(s, str):
        s = str(s or "")
    return bool(_NON_ASCII_RE.search(s))


def substring_between(s: str | None, start_tag: str, end_tag: str) -> str | None:
    """Return substring between start_tag and end_tag, or None."""
    if not s:
        return None
    start = s.find(start_tag)
    if start == -1:
        return None
    start += len(start_tag)
    end = s.find(end_tag, start)
    if end != -1:
        return s[start:end]
    return None


# -------------------------
# Filesystem helpers
# -------------------------


def list_text_rule_files(directory: str | Path) -> list[Path]:
    """Return alphabetical list of *.txt files inside `directory`."""
    base = Path(directory)
    if not base.is_dir():
        raise FileNotFoundError(f"Input directory not found: {directory}")
    return [
        entry
        for entry in sorted(base.iterdir(), key=lambda p: p.name.lower())
        if entry.is_file() and entry.suffix.lower() == ".txt"
    ]


def summarize_stats(
    stats_list: list[dict[str, int | str]], keys: Sequence[str]
) -> dict[str, int]:
    """Aggregate totals for the provided keys across a list of stats dicts."""
    return {key: sum(int(s.get(key, 0)) for s in stats_list) for key in keys}


def format_summary(
    label: str, stats_list: list[dict[str, int | str]], keys: Sequence[str]
) -> str:
    """Return a space-joined summary string matching existing CLI output."""
    totals = summarize_stats(stats_list, keys)
    parts = [f"{label}: files={len(stats_list)}"]
    parts.extend(f"{key}={totals.get(key, 0)}" for key in keys)
    return " ".join(parts)


def process_text_rule_files(
    input_path: str | Path,
    output_path: str | Path,
    job_builder: Callable[[Path, Path], tuple],
    worker: Callable[[tuple], dict[str, int | str]],
    parallel: bool = True,
) -> list[dict[str, int | str]]:
    """
    Apply a worker to text files under input_path, mirroring input/output layout.

    job_builder should return the argument tuple expected by worker.
    """
    inp = Path(input_path)
    outp = Path(output_path)
    results: list[dict[str, int | str]] = []

    if inp.is_dir():
        outp.mkdir(parents=True, exist_ok=True)
        pairs = [(entry, outp / entry.name) for entry in list_text_rule_files(inp)]
        if not pairs:
            return results
        jobs = [job_builder(src, dest) for src, dest in pairs]
        if parallel and len(jobs) > 1:
            max_workers = min(os.cpu_count() or 1, len(jobs))
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                for res in executor.map(worker, jobs):
                    results.append(res)
        else:
            for job in jobs:
                results.append(worker(job))
    elif inp.is_file():
        dest = outp / inp.name if outp.is_dir() else outp
        dest.parent.mkdir(parents=True, exist_ok=True)
        job = job_builder(inp, dest)
        results.append(worker(job))
    else:
        raise FileNotFoundError(f"Input path not found: {input_path}")

    return results


# -------------------------
# Cached conversions
# -------------------------


@lru_cache(maxsize=DOMAIN_CACHE_SIZE)
def to_punycode(domain: str) -> str:
    """Convert domain (possibly Unicode) to IDNA/punycode; on failure return
    original."""
    if not isinstance(domain, str) or domain == "":
        return domain
    try:
        return domain.encode("idna").decode("ascii")
    except Exception:
        return domain


@lru_cache(maxsize=DOMAIN_CACHE_SIZE)
def _normalize_domain_token_cached(domain: str) -> str:
    """Normalize domain: lowercase, strip wildcard/trailing dots, and punycode if
    needed."""
    d = domain.strip().lower()
    if d.startswith("*."):
        d = d[2:]
    d = d.rstrip(".")
    # Fast path: check if ASCII before regex (common case optimization)
    if not d.isascii():
        try:
            d = d.encode("idna").decode("ascii")
        except Exception:
            pass
    return d


def normalize_domain_token(domain: str | None) -> str:
    """Normalize domain token for deduplication and comparison (cached internally)."""
    if not domain or not domain.strip():
        return ""
    return _normalize_domain_token_cached(domain)


# -------------------------
# Split by delimiter with escape char
# -------------------------


def split_by_delimiter_with_escape_character(
    s: str | None,
    delimiter: str,
    escape_character: str,
    preserve_all_tokens: bool,
) -> list[str]:
    """
    Equivalent to Hostlist Compiler's splitByDelimiterWithEscapeCharacter.
    Escapes delimiters preceded by the escape character.
    """
    parts: list[str] = []
    if not s:
        return parts

    sb: list[str] = []
    append_sb = sb.append
    pop_sb = sb.pop
    append_parts = parts.append

    for i, ch in enumerate(s):
        prev = s[i - 1] if i > 0 else ""
        if ch == delimiter:
            if i == 0:
                continue
            elif prev == escape_character:
                if sb:
                    pop_sb()
                append_sb(ch)
            elif preserve_all_tokens or sb:
                append_parts("".join(sb))
                sb.clear()
        else:
            append_sb(ch)

    if preserve_all_tokens or sb:
        append_parts("".join(sb))
    return parts


# /etc/hosts parsing
# -------------------------


def is_etc_hosts_rule(line: str) -> bool:
    """Return True if line matches /etc/hosts syntax."""
    return bool(line and _ETC_HOSTS_REGEX.match(line.strip()))


def load_etc_hosts_rule_properties(rule_text: str) -> dict:
    """Parse /etc/hosts-style rule; returns {'ruleText', 'ip', 'hostnames'}."""
    if rule_text is None:
        raise TypeError("rule_text is None")
    rule = rule_text.strip()
    if "#" in rule and rule.find("#") > 0:
        rule = rule[: rule.find("#")]
    parts = rule.strip().split()
    if len(parts) < 2:
        raise TypeError(f"Invalid /etc/hosts rule: {rule_text}")
    return {"ruleText": rule_text, "ip": parts[0], "hostnames": parts[1:]}


def canonicalize_ip(ip_raw: str) -> str | None:
    """Return canonical IP string, stripping brackets/zone IDs; None if invalid."""
    if not ip_raw:
        return None
    cand = ip_raw.strip().strip("[]")
    if "%" in cand:
        cand = cand.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(cand))
    except ValueError:
        return None


# -------------------------
# Domain suffix helpers
# -------------------------


def walk_suffixes(domain: str) -> Iterator[str]:
    """
    Yield domain and successive parent suffixes (e.g., a.b.c → a.b.c, b.c, c).
    
    Args:
        domain: Domain string to walk
        
    Yields:
        Domain and each parent suffix in order
    """
    if not domain:
        return
    cur = domain
    yield cur
    idx = cur.find(".")
    while idx != -1:
        cur = cur[idx + 1:]
        yield cur
        idx = cur.find(".")


def has_parent_domain(domain: str, domain_set: set[str]) -> bool:
    """
    Return True if any parent of `domain` exists in domain_set.

    Example:
        has_parent_domain("a.b.c", {"b.c"}) -> True
    """
    if not domain or not domain_set:
        return False
    parts = domain.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in domain_set:
            return True
    return False


def minimal_covering_set(domains: set[str]) -> set[str]:
    """
    Return the smallest subset that covers all domains (remove redundant subdomains).

    Example:
        {"a.b.c", "b.c"} -> {"b.c"}
    """
    ordered = sorted(domains, key=lambda d: (d.count("."), len(d)))
    minimal: set[str] = set()
    for domain in ordered:
        if not has_parent_domain(domain, minimal):
            minimal.add(domain)
    return minimal


def _extract_plain_domain_candidate(
    line: str,
    normalize: Callable[[str], str],
    domain_regex: re.Pattern[str],
    is_hosts_rule: Callable[[str], bool],
    covered_by_abp: Callable[[str], bool],
) -> str:
    """
    Return a normalized plain-domain candidate or an empty string if the line
    should be ignored for plain-domain minimal-set building.
    """
    if (
        not line
        or line.startswith("@@")
        or line.startswith(DOMAIN_PREFIX)
        or is_hosts_rule(line)
        or "." not in line
        or not domain_regex.match(line)
    ):
        return ""
    dn = normalize(line)
    if not dn or covered_by_abp(dn):
        return ""
    return dn


def build_plain_domain_minimal_set(
    file_lines_cache: dict[str, list[str]],
    normalize: Callable[[str], str],
    domain_regex: re.Pattern[str],
    is_hosts_rule: Callable[[str], bool],
    covered_by_abp: Callable[[str], bool],
) -> set[str]:
    """
    Given cached lines from all input files, return the minimal covering set of
    plain domains.

    Args:
        file_lines_cache: Mapping of filename -> list of lines (already stripped).
        normalize: Function to normalize individual domain tokens.
        domain_regex: Precompiled regex to validate plain domains.
        is_hosts_rule: Predicate identifying /etc/hosts-style rules.
        covered_by_abp: Predicate reporting whether a domain is covered by ABP rules.
    """
    plain_domains: set[str] = set()
    for lines in file_lines_cache.values():
        for line in lines:
            candidate = _extract_plain_domain_candidate(
                line, normalize, domain_regex, is_hosts_rule, covered_by_abp
            )
            if candidate:
                plain_domains.add(candidate)
    return minimal_covering_set(plain_domains)


def is_domain_covered_by_wildcard(domain: str, wildcard_roots: set[str]) -> bool:
    """
    Return True if `domain` is covered by a wildcard in `wildcard_roots`.

    Example:
        wildcard_roots = {"example.com"}
        is_domain_covered_by_wildcard("foo.example.com", wildcard_roots) -> True
        is_domain_covered_by_wildcard("example.com", wildcard_roots) -> False
    """
    if not domain or not wildcard_roots or "." not in domain:
        return False
    parts = domain.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in wildcard_roots:
            return True
    return False


# -------------------------
# Unescaped-char helpers
# -------------------------


def find_unescaped_char(s: str, ch: str, start: int = 0) -> int:
    """Return index of first unescaped occurrence of ch after start."""
    i = start
    while i < len(s):
        if s[i] == ch:
            j = i - 1
            backslashes = 0
            while j >= 0 and s[j] == "\\":
                backslashes += 1
                j -= 1
            if backslashes % 2 == 0:
                return i
        i += 1
    return -1


def find_last_unescaped_dollar(s: str, start: int = 0) -> int:
    """Return last index of unescaped '$' after start."""
    i = len(s) - 1
    while i >= start:
        if s[i] == "$":
            j = i - 1
            backslashes = 0
            while j >= 0 and s[j] == "\\":
                backslashes += 1
                j -= 1
            if backslashes % 2 == 0:
                return i
        i -= 1
    return -1


# -------------------------
# Adblock-style parsing
# -------------------------


def parse_rule_tokens(rule_text: str) -> dict[str, str | None]:
    """Split adblock rule into pattern, options, and whitelist parts."""
    if rule_text is None:
        raise TypeError("rule_text is None")

    s = rule_text.strip()
    tokens = {"pattern": None, "options": None, "whitelist": False}
    start_index = 0

    if s.startswith("@@"):
        tokens["whitelist"] = True
        start_index = 2
    if len(s) <= start_index:
        raise TypeError(f"the rule is too short: {rule_text}")

    tokens["pattern"] = s[start_index:]
    pat = tokens["pattern"]

    if pat.startswith("/") and pat.endswith("/") and "replace=" not in pat:
        return tokens

    last_d = find_last_unescaped_dollar(s, start=start_index)
    if last_d != -1:
        tokens["pattern"] = s[start_index:last_d]
        tokens["options"] = s[last_d + 1 :]
    else:
        tokens["pattern"] = s[start_index:]
    return tokens


def extract_hostname(pattern: str | None) -> str | None:
    """Extract hostname from '||domain^' pattern."""
    if not pattern:
        return None
    m = _ABP_HOSTNAME_RE.match(pattern.strip())
    return m.group(1) if m else None


def _build_option_entry(option_token: str) -> dict[str, str | None]:
    """Return a {'name', 'value'} mapping for a single option token."""
    if "=" in option_token:
        name, val = option_token.split("=", 1)
        return {"name": name, "value": val}
    return {"name": option_token, "value": None}


def load_adblock_rule_properties(rule_text: str) -> dict:
    """Parse Adblock-style rule into structured components."""
    tokens = parse_rule_tokens(rule_text.strip())
    rule = {
        "ruleText": rule_text,
        "pattern": tokens.get("pattern"),
        "whitelist": tokens.get("whitelist", False),
        "options": None,
        "hostname": extract_hostname(tokens.get("pattern") or ""),
    }

    opts_raw = tokens.get("options")
    if opts_raw:
        parts = split_by_delimiter_with_escape_character(opts_raw, ",", "\\", False)
        if parts:
            opts_list: list[dict[str, str | None]] = []
            for opt in parts:
                opts_list.append(_build_option_entry(opt))
            rule["options"] = opts_list

    return rule


# -------------------------
# Domain & IP helpers
# -------------------------


def convert_non_ascii_to_punycode(line: str) -> str:
    """Replace domain-like substrings with punycode equivalents (no-op for
    ASCII)."""
    if not _NON_ASCII_RE.search(line):
        return line

    def _repl(m: re.Match) -> str:
        wildcard = m.group(1) or ""
        domain = m.group(2)
        if _NON_ASCII_RE.search(domain):
            return wildcard + to_punycode(domain)
        return m.group(0)

    try:
        return _DOMAIN_PATTERN_RE.sub(_repl, line)
    except re.error:
        return line


@lru_cache(maxsize=8192)
def is_just_domain(token: str) -> bool:
    """Return True if token is a syntactically valid domain (strict match)."""
    if not token:
        return False
    t = token.strip().lower().strip(".")
    return bool(_DOMAIN_REGEX.fullmatch(t))

# Exports
# -------------------------

__all__ = [
    # Functions
    "is_blank_line",
    "is_comment_line",
    "list_text_rule_files",
    "contains_non_ascii_characters",
    "substring_between",
    "split_by_delimiter_with_escape_character",
    "is_etc_hosts_rule",
    "load_etc_hosts_rule_properties",
    "canonicalize_ip",
    "parse_rule_tokens",
    "extract_hostname",
    "load_adblock_rule_properties",
    "convert_non_ascii_to_punycode",
    "normalize_domain_token",
    "to_punycode",
    "is_just_domain",
    "find_unescaped_char",
    "find_last_unescaped_dollar",
    "walk_suffixes",
    "has_parent_domain",
    "minimal_covering_set",
    "is_domain_covered_by_wildcard",
    # Constants
    "DOMAIN_PREFIX",
    "DOMAIN_SEPARATOR",
    "WILDCARD",
    "ELEMENT_HIDING_MARKERS",
    "DOMAIN_CACHE_SIZE",
    "IO_BUFFER_SIZE",
    "REMOVE_COMMENTS_STATS_KEYS",
    "VALIDATE_STATS_KEYS",
    "REMOVE_COMMENTS_SUMMARY_ORDER",
    "VALIDATE_SUMMARY_ORDER",
    # Regex patterns
    "DOMAIN_REGEX",
    "ETC_HOSTS_REGEX",
    "ABP_HOSTNAME_RE",
    "NON_ASCII_RE",
    "ELEMENT_HIDING_PATTERN_RE",
    # Shared helpers
    "summarize_stats",
    "format_summary",
    "process_text_rule_files",
]

# Lint-safe alias for backward compatibility
rule_utils = sys.modules[__name__]
