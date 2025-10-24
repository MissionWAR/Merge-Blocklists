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
import re
import sys
from functools import lru_cache
from typing import Iterator


# -------------------------
# Precompiled regexes & constants
# -------------------------

# AdGuard syntax constants (shared across scripts)
DOMAIN_PREFIX = "||"
DOMAIN_SEPARATOR = "^"
WILDCARD = "*"
ELEMENT_HIDING_MARKERS = ("##", "#@#", "#%#")

# Performance tuning constants
DOMAIN_CACHE_SIZE = 32768  # LRU cache size for domain normalization (supports 5M+ domains)
IO_BUFFER_SIZE = 131072  # 128KB buffer for file I/O (optimized for modern SSDs)

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
_ELEMENT_HIDING_PATTERN_RE = re.compile(r"##|#@#|#%#")  # Optimized pattern matching for element hiding markers

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


def is_rule_whitelisted(rule_text: str | None) -> bool:
    """Return True if rule is an exception rule starting with '@@'."""
    return bool(rule_text and rule_text.strip().startswith("@@"))


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
# Cached conversions
# -------------------------


@lru_cache(maxsize=DOMAIN_CACHE_SIZE)
def to_punycode(domain: str) -> str:
    """Convert domain (possibly Unicode) to IDNA/punycode; on failure return original."""
    if not isinstance(domain, str) or domain == "":
        return domain
    try:
        return domain.encode("idna").decode("ascii")
    except Exception:
        return domain


@lru_cache(maxsize=DOMAIN_CACHE_SIZE)
def _normalize_domain_token_cached(domain: str) -> str:
    """Normalize domain: lowercase, strip wildcard/trailing dots, and punycode if needed."""
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


# -------------------------
# Wildcard helper
# -------------------------


class Wildcard:
    """Matches plain substring, '*' wildcard, or /regex/ patterns."""

    def __init__(self, s: str):
        if not s:
            raise TypeError("Wildcard cannot be empty")
        self.plain = s
        self.regex: re.Pattern | None = None

        if s.startswith("/") and s.endswith("/") and len(s) > 2:
            inner = s[1:-1]
            self.regex = re.compile(inner, flags=re.I | re.M)
        elif "*" in s:
            parts = [re.escape(p) for p in re.split(r"\*+", s)]
            pattern = r"^" + r".*".join(parts) + r"$"
            self.regex = re.compile(pattern, flags=re.I | re.S)

    def test(self, s: str) -> bool:
        if not isinstance(s, str):
            raise TypeError("Invalid argument passed to Wildcard.test")
        if self.regex is not None:
            return bool(self.regex.search(s))
        return self.plain in s

    def __str__(self) -> str:
        return self.plain

    __repr__ = __str__


# -------------------------
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
                if "=" in opt:
                    name, val = opt.split("=", 1)
                    opts_list.append({"name": name, "value": val})
                else:
                    opts_list.append({"name": opt, "value": None})
            rule["options"] = opts_list

    return rule


def find_modifier(
    rule_options: list[dict[str, str | None]] | None, name: str
) -> dict[str, str | None] | None:
    """Find modifier dict by name from a list of rule options."""
    if not rule_options:
        return None
    for opt in rule_options:
        if opt.get("name") == name:
            return opt
    return None


def remove_modifier(rule_options: list[dict[str, str | None]], name: str) -> bool:
    """Remove modifiers with matching name in-place."""
    found = False
    i = len(rule_options) - 1
    while i >= 0:
        if rule_options[i].get("name") == name:
            rule_options.pop(i)
            found = True
        i -= 1
    return found


def adblock_rule_to_string(rule_props: dict) -> str:
    """Reconstruct adblock rule string from parsed properties."""
    out: list[str] = []
    append_out = out.append
    if rule_props.get("whitelist"):
        append_out("@@")
    append_out(rule_props.get("pattern") or "")
    opts = rule_props.get("options")
    if opts:
        append_out("$")
        # Optimized: build options list once instead of incremental appends
        opt_parts = []
        for opt in opts:
            name = opt.get("name") or ""
            val = opt.get("value")
            if val is not None:
                opt_parts.append(f"{name}={val}")
            else:
                opt_parts.append(name)
        append_out(",".join(opt_parts))
    return "".join(out)


# -------------------------
# Domain & IP helpers
# -------------------------


def convert_non_ascii_to_punycode(line: str) -> str:
    """Replace domain-like substrings with punycode equivalents (no-op for ASCII)."""
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


def is_ip_pattern(pattern: str | None) -> str | None:
    """Return canonical IP if pattern is like '||IP^' else None."""
    if not pattern:
        return None
    m = _ABP_HOSTNAME_RE.match(pattern.strip())
    if not m:
        return None
    inner = m.group(1).strip().strip("[]")
    if "%" in inner:
        inner = inner.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(inner))
    except Exception:
        return None

# Exports
# -------------------------

__all__ = [
    # Functions
    "is_blank_line",
    "is_comment_line",
    "is_rule_whitelisted",
    "contains_non_ascii_characters",
    "substring_between",
    "split_by_delimiter_with_escape_character",
    "Wildcard",
    "is_etc_hosts_rule",
    "load_etc_hosts_rule_properties",
    "canonicalize_ip",
    "parse_rule_tokens",
    "extract_hostname",
    "load_adblock_rule_properties",
    "find_modifier",
    "remove_modifier",
    "adblock_rule_to_string",
    "convert_non_ascii_to_punycode",
    "normalize_domain_token",
    "to_punycode",
    "is_ip_pattern",
    "is_just_domain",
    "find_unescaped_char",
    "find_last_unescaped_dollar",
    "walk_suffixes",
    # Constants
    "DOMAIN_PREFIX",
    "DOMAIN_SEPARATOR",
    "WILDCARD",
    "ELEMENT_HIDING_MARKERS",
    "DOMAIN_CACHE_SIZE",
    "IO_BUFFER_SIZE",
    # Regex patterns
    "DOMAIN_REGEX",
    "ETC_HOSTS_REGEX",
    "ABP_HOSTNAME_RE",
    "NON_ASCII_RE",
    "ELEMENT_HIDING_PATTERN_RE",
]

# Lint-safe alias for backward compatibility
rule_utils = sys.modules[__name__]
