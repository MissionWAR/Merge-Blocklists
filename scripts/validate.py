#!/usr/bin/env python3
"""
Validate AdGuard Home compatible DNS filtering rules.

Validates:
- AdBlock syntax (||example.com^, with options)
- /etc/hosts format (0.0.0.0 example.com)
- Element hiding rules (##.selector)
- Regex patterns (/pattern/)
- Modifier support (dnstype, dnsrewrite, ctag, client, etc.)

Filters Out:
- Invalid hostnames
- Unsupported modifiers (network-level filtering)
- Malformed rules
- Rules with excessive complexity

Usage:
    # As module
    from scripts.validate import valid
    is_valid = valid("||example.com^", allowed_ip=True, stats={})
    
    # As CLI
    python -m scripts.validate input_dir/ output_dir/
    
    # Parallel processing (uses all CPU cores)
    Processes ~100k-500k rules/second depending on complexity

Examples:
    Valid Rules:
        ||example.com^
        ||example.com^$important
        0.0.0.0 example.com
        127.0.0.1 localhost
        /^https:\\/\\/example\\.com/
        ||*.example.com^  (wildcard TLD for spam domains)
    
    Invalid Rules:
        ||example^  (missing domain structure)
        ||example.com^$script  (network modifier not supported for DNS)
        example  (plain text without proper format)
"""
from __future__ import annotations

import ipaddress
import multiprocessing as mp
import re
import sys
import tempfile
from pathlib import Path

from scripts import utils

# Import shared constants from utils
IO_BUFFER_SIZE = utils.IO_BUFFER_SIZE


# -------------------------
# Configuration
# -------------------------
# Import constants from utils to avoid duplication
DOMAIN_PREFIX = utils.DOMAIN_PREFIX
DOMAIN_SEPARATOR = utils.DOMAIN_SEPARATOR
WILDCARD = utils.WILDCARD
ELEMENT_HIDING_MARKERS = utils.ELEMENT_HIDING_MARKERS

# RFC 1035 DNS hostname limits
MAX_HOSTNAME_LENGTH = 255  # Maximum total hostname length
MAX_LABEL_LENGTH = 63      # Maximum length per label (between dots)

# Supported modifiers for DNS-level filtering (AdGuard Home)
# Using frozenset for O(1) lookup performance and immutability
SUPPORTED_MODIFIERS = frozenset({
    "important",   # Priority control
    "ctag",        # Client tag filtering
    "dnstype",     # DNS record type
    "dnsrewrite",  # Custom DNS responses
    "denyallow",   # Exception domains
    "badfilter",   # Disable another filter
    "client",      # Client-specific rules
})

# Modifiers that require allow_ip=True
LIMITING_MODIFIERS = frozenset({"denyallow", "badfilter", "client"})

# -------------------------
# Local-only regexes (not in utils)
# -------------------------
_DOMAIN_ALLOWED_CHARS_RE = re.compile(r"^[a-zA-Z0-9\-\.\*\|\^:\/]+$")
_IP_ALLOWED_CHARS = frozenset("0123456789.:[]abcdefABCDEF%")


# -------------------------
# Small helpers
# -------------------------
# Use utils version for consistency and better performance
_contains_non_ascii = utils.contains_non_ascii_characters


def _to_ascii_domain(domain: str) -> str:
    """
    Convert a domain to ASCII (punycode) for validation.
    Preserve leading '*.' and bracketed IPv6. On failure, return original input.
    """
    if not domain:
        return domain
    d = domain.strip()
    wildcard = ""
    if d.startswith("*."):
        wildcard = "*."
        d = d[2:]
    if d.startswith("[") and d.endswith("]"):
        return wildcard + d
    try:
        return wildcard + d.encode("idna").decode("ascii")
    except Exception:
        return wildcard + domain


# Use utils implementations instead of local duplicates
substring_between = utils.substring_between
_find_unescaped_char = utils.find_unescaped_char
_find_last_unescaped_dollar = utils.find_last_unescaped_dollar


def _count_preceding_backslashes(s: str, idx: int) -> int:
    """Count consecutive backslashes immediately before position idx in s."""
    j = idx - 1
    count = 0
    while j >= 0 and s[j] == "\\":
        count += 1
        j -= 1
    return count


def split_options_with_escape(opt_text: str) -> list[str]:
    """
    Split options by unescaped commas (honor backslash-escaped commas).
    Trim tokens and drop empty ones.
    """
    if not opt_text:
        return []
    parts: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(opt_text)
    while i < n:
        c = opt_text[i]
        if c == ",":
            bs = _count_preceding_backslashes(opt_text, i)
            if bs % 2 == 1:
                # escaped comma -> keep comma (remove single escape backslash if present in buf)
                if buf and buf[-1] == "\\":
                    buf.pop()
                buf.append(",")
            else:
                token = "".join(buf).strip()
                if token:
                    parts.append(token)
                buf = []
        else:
            buf.append(c)
        i += 1
    token = "".join(buf).strip()
    if token:
        parts.append(token)
    return parts


# -------------------------
# Adblock-style parsing (use utils implementation)
# -------------------------
# Use utils.parse_rule_tokens as the base implementation
_parse_adblock_tokens = utils.parse_rule_tokens


def load_adblock_rule_properties(rule_text: str) -> dict:
    """
    Return structured properties for adblock-style rules:
      { ruleText, pattern, whitelist, options: [{name, value}, ...] | None, hostname | None }
    """
    tokens = _parse_adblock_tokens(rule_text)
    props: dict = {
        "ruleText": rule_text,
        "pattern": tokens["pattern"],
        "whitelist": tokens["whitelist"],
        "options": None,
        "hostname": None,
    }

    if tokens.get("options"):
        parts = split_options_with_escape(tokens["options"])
        opts = []
        for p in parts:
            if "=" in p:
                name, value = p.split("=", 1)
                name = name.strip().lower()
                value = value.strip() if value is not None else None
            else:
                name = p.strip().lower()
                value = None
            if name:
                opts.append({"name": name, "value": value})
        if opts:
            props["options"] = opts

    m = utils.ABP_HOSTNAME_RE.match(props.get("pattern") or "")
    props["hostname"] = m.group(1).lower() if m else None
    return props


# -------------------------
# Line classification helpers
# -------------------------
# Use utils.is_comment_line for consistency (handles !, #, and separator lines)
is_comment_line = utils.is_comment_line
# Use utils.is_blank_line for consistency (simpler and faster than regex)
is_blank_line = utils.is_blank_line


def _is_element_hiding(rule_text: str) -> bool:
    """Detect element-hiding/scriptlet markers anywhere in the rule."""
    return any(marker in rule_text for marker in ELEMENT_HIDING_MARKERS)


def _pattern_is_regex_literal(pattern: str) -> bool:
    """
    Return True if the pattern is a raw /regex/ literal (without replace= modifiers).
    """
    return (
        pattern.startswith("/")
        and _find_unescaped_char(pattern, "/", start=1) != -1
        and "replace=" not in pattern
    )


def _has_only_allowed_characters(pattern: str) -> bool:
    """Ensure the pattern sticks to characters supported for DNS filtering."""
    return bool(_DOMAIN_ALLOWED_CHARS_RE.match(pattern.removeprefix("://")))


def _has_invalid_wildcard_combo(pattern: str, separator_idx: int) -> bool:
    """Return True if a '*' appears after '^' (invalid for DNS-style blocking rules)."""
    wildcard_idx = pattern.find(WILDCARD)
    return (
        separator_idx != -1
        and wildcard_idx != -1
        and wildcard_idx > separator_idx
    )


def _is_domain_anchored_pattern(pattern: str, separator_idx: int) -> bool:
    """Return True if the pattern represents a '||domain^' style rule."""
    return pattern.startswith(DOMAIN_PREFIX) and separator_idx != -1


def _pattern_has_valid_terminator(pattern: str, separator_idx: int) -> bool:
    """Return True if no invalid characters follow the '^' terminator."""
    return not (
        pattern
        and len(pattern) > separator_idx + 1
        and pattern[separator_idx + 1] != "|"
    )


def _validate_supported_modifiers(
    options: list[dict[str, str | None]] | None, stats: dict[str, int]
) -> tuple[bool, bool]:
    """
    Validate modifiers. Returns (is_valid, has_limiting_modifier).
    """
    has_limit_modifier = False
    if not options:
        return True, has_limit_modifier

    for opt in options:
        name = opt["name"]
        if name not in SUPPORTED_MODIFIERS:
            stats["removed_bad_modifier"] += 1
            return False, False
        if name in LIMITING_MODIFIERS:
            has_limit_modifier = True
    return True, has_limit_modifier


def _handle_wildcard_domain(
    domain_token: str, stats: dict[str, int]
) -> tuple[bool, bool]:
    """
    Handle wildcard-containing domains.

    Returns:
        (handled, keep_rule)
        handled=True when the domain contains '*'.
        keep_rule indicates whether the wildcard was accepted.
    """
    if "*" not in domain_token:
        return False, False
    if domain_token.startswith("*.") and domain_token.count("*") == 1:
        stats["kept_wildcard_tld"] += 1
        return True, True
    stats["removed_malformed"] += 1
    return True, False


# -------------------------
# Validation checks
# -------------------------
def valid_hostname(
    hostname: str, rule_text: str, allowed_ip: bool, _has_limit_modifier: bool
) -> bool:
    """
    Validate a hostname token (IDN-aware). Accept TLDs and wildcard patterns where appropriate.

    Note: `_has_limit_modifier` is accepted for parity with the original HostlistCompiler
    semantics and retained for future use; it is intentionally not used to alter
    validation behavior in this implementation (underscore prefix signals intentional non-use).
    """
    if not hostname:
        return False

    host_for_ip = hostname.strip()
    if host_for_ip.startswith("[") and host_for_ip.endswith("]"):
        host_for_ip_unbr = host_for_ip[1:-1]
    else:
        host_for_ip_unbr = host_for_ip

    # IP detection with fast path optimization
    # Quick check: IPs only contain digits, dots, colons, brackets, and hex chars (for IPv6)
    # This avoids expensive ipaddress parsing for obvious non-IPs (e.g., "example.com")
    is_ip = False
    if all(c in _IP_ALLOWED_CHARS for c in host_for_ip):
        # Potential IP - now do full validation
        try:
            ipaddress.ip_address(host_for_ip_unbr)
            is_ip = True
        except Exception:
            pass  # Not an IP after all

    if is_ip and not allowed_ip:
        return False

    to_check = hostname
    if _contains_non_ascii(hostname):
        to_check = _to_ascii_domain(hostname)

    # strip trailing dot if present
    if to_check.endswith(".") and len(to_check) > 1:
        to_check = to_check[:-1]

    if utils.DOMAIN_REGEX.match(to_check):
        return True

    # permissive single-label fallback (common in some lists)
    return bool(re.fullmatch(r"^[A-Za-z0-9_\-]+$", to_check))


def valid_etc_hosts_rule(rule_text: str, allow_ip: bool) -> bool:
    """Validate a /etc/hosts-style rule (IP followed by hostnames)."""
    m = utils.ETC_HOSTS_REGEX.match(rule_text.strip())
    if not m:
        return False
    hostnames_raw = m.group(2)  # Note: utils regex uses group(2) for hostnames
    hostnames = [h.strip() for h in hostnames_raw.split() if h.strip()]
    if not hostnames:
        return False
    return all(valid_hostname(h, rule_text, allow_ip, False) for h in hostnames)


def valid_adblock_rule(rule_text: str, allowed_ip: bool, stats: dict[str, int]) -> bool:
    """
    Validate adblock-style rules for DNS-level filtering.
    Updates stats counters for removed/kept categories.
    """
    if _is_element_hiding(rule_text):
        stats["removed_element_hiding"] += 1
        return False

    try:
        props = load_adblock_rule_properties(rule_text)
    except Exception:
        stats["removed_malformed"] += 1
        return False

    modifiers_ok, has_limit_modifier = _validate_supported_modifiers(
        props.get("options"), stats
    )
    if not modifiers_ok:
        return False

    pat = props.get("pattern") or ""

    if _pattern_is_regex_literal(pat):
        stats["kept_regex"] += 1
        return True

    if not _has_only_allowed_characters(pat):
        stats["removed_malformed"] += 1
        return False

    sep_idx = pat.find(DOMAIN_SEPARATOR)
    if _has_invalid_wildcard_combo(pat, sep_idx):
        stats["removed_malformed"] += 1
        return False

    if not _is_domain_anchored_pattern(pat, sep_idx):
        stats["kept_other_adblock"] += 1
        return True

    domain_to_check = substring_between(
        props.get("pattern") or "", DOMAIN_PREFIX, DOMAIN_SEPARATOR
    )
    if domain_to_check is None:
        stats["removed_malformed"] += 1
        return False

    wildcard_handled, wildcard_allowed = _handle_wildcard_domain(
        domain_to_check, stats
    )
    if wildcard_handled:
        return wildcard_allowed

    if not valid_hostname(domain_to_check, rule_text, allowed_ip, has_limit_modifier):
        stats["removed_invalid_host"] += 1
        return False

    if not _pattern_has_valid_terminator(pat, sep_idx):
        stats["removed_malformed"] += 1
        return False

    stats["kept_adblock_domain"] += 1
    return True


def _is_pure_regex_line(s: str) -> bool:
    """
    Detect if the (trimmed) line is a regex literal (possibly prefixed by @@).
    Handles flags and flags+options.
    """
    if not s:
        return False
    t = s.strip()
    if t.startswith("@@"):
        t = t[2:].lstrip()
    if not t.startswith("/"):
        return False
    end = _find_unescaped_char(t, "/", start=1)
    if end == -1:
        return False
    # avoid treating replace= inside the regex literal as pure regex
    if "replace=" in t[: end + 1]:
        return False
    dollar_after = _find_last_unescaped_dollar(t, start=end + 1)
    flags_part = t[end + 1 : dollar_after if dollar_after != -1 else len(t)].strip()
    return flags_part == "" or flags_part.isalpha()


def valid(rule_text: str, allowed_ip: bool, stats: dict[str, int]) -> bool:
    """Top-level validity check. Returns True if the rule should be kept."""

    # Remove blank lines (whitespace-only) unconditionally (you asked to drop blank lines).
    if is_blank_line(rule_text):
        # caller (Validator) will account for removed_empty stat
        return False

    # Preserve explicit comments (starting with '!' or '#') here — Validator will still drop
    # comments immediately preceding removed rules. This keeps parity with hostlist compiler,
    # while removing blank lines only.
    if is_comment_line(rule_text):
        return True

    trimmed = rule_text.strip()

    # Pure regex lines are accepted early (no compilation check) to mirror Hostlist Compiler behaviour.
    if _is_pure_regex_line(trimmed):
        stats["kept_regex"] += 1
        return True

    # /etc/hosts rule
    if utils.ETC_HOSTS_REGEX.match(trimmed):
        ok = valid_etc_hosts_rule(trimmed, allowed_ip)
        if ok:
            stats["kept_hosts"] += 1
        else:
            stats["removed_invalid_host"] += 1
        return ok

    # adblock-style
    return valid_adblock_rule(trimmed, allowed_ip, stats)


# -------------------------
# Backwards-pass Validator (optimized O(n))
# -------------------------
class Validator:
    """Remove invalid rules and drop any immediately preceding comments/empty lines."""

    def __init__(self, allowed_ip: bool):
        self.previous_rule_removed = False
        self.allowed_ip = allowed_ip

    def validate(self, rules: list[str], stats: dict[str, int]) -> list[str]:
        """
        Perform a backward pass over the list, removing invalid rules.

        Implemented in a linear-time reversed-append pass (avoid O(n^2) popping).
        """
        result_reversed: list[str] = []
        prev_removed = False

        # Walk from end to start
        for ln in reversed(rules):
            is_blank = is_blank_line(ln)
            is_comment = is_comment_line(ln)
            is_comment_or_blank = is_comment or is_blank

            is_valid_rule = valid(ln, self.allowed_ip, stats)

            if not is_valid_rule:
                # If it's blank, count as removed_empty; if non-comment invalid rule, count removed_invalid.
                if is_blank:
                    stats["removed_empty"] += 1
                elif not is_comment:
                    # non-comment invalid rule (malformed, element-hiding, etc.)
                    stats["removed_invalid"] += 1
                else:
                    # explicit comment that valid() returned False for (rare), count as removed_comment
                    stats["removed_comments"] += 1
                prev_removed = True
                continue

            # If a previous rule was removed, drop any comment/blank line immediately preceding it.
            if prev_removed and is_comment_or_blank:
                if is_comment:
                    stats["removed_comments"] += 1
                else:
                    stats["removed_empty"] += 1
                # keep prev_removed True so we continue removing sequential comment/blank
                continue

            # otherwise keep the line
            prev_removed = False
            result_reversed.append(ln)

        # reverse to return original order
        return list(reversed(result_reversed))


# -------------------------
# File processing & transforms
# -------------------------
def process_file(in_path: str, out_path: str, allow_ip: bool = True) -> dict[str, int | str]:
    """
    Read entire file (backwards-pass requires full list), validate, and write filtered output.

    Note: function signature is preserved for compatibility with existing workflow calls.
    """
    stats: dict[str, int | str] = {
        "in_path": in_path,
        "out_path": out_path,
        "lines_in": 0,
        "lines_out": 0,
        "removed_invalid": 0,
        "removed_element_hiding": 0,
        "removed_bad_modifier": 0,
        "removed_invalid_host": 0,
        "removed_malformed": 0,
        "kept_regex": 0,
        "kept_hosts": 0,
        "kept_adblock_domain": 0,
        "kept_wildcard_tld": 0,
        "kept_other_adblock": 0,
        "removed_comments": 0,
        "removed_empty": 0,
    }

    in_path_p = Path(in_path)
    with in_path_p.open(
        "r", encoding="utf-8", errors="surrogateescape", buffering=IO_BUFFER_SIZE
    ) as fr:
        lines = fr.readlines()
        lines = [ln.rstrip("\n\r") for ln in lines]
    stats["lines_in"] = len(lines)

    validator = Validator(allow_ip)
    filtered = validator.validate(lines, stats)
    stats["lines_out"] = len(filtered)
    out_path_p = Path(out_path)
    out_dir = out_path_p.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    # Atomic write using a NamedTemporaryFile and Path.replace
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        newline="\n",
        dir=out_dir,
        prefix=".tmp_validate_",
        delete=False,
        buffering=IO_BUFFER_SIZE,  # 128KB buffer optimized for modern SSDs
    ) as tmp_file:
        tmp_path = Path(tmp_file.name)
        try:
            for ln in filtered:
                tmp_file.write(ln + "\n")
            tmp_file.flush()
            tmp_path.replace(out_path_p)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise

    return stats


def _process_file_worker(args: tuple[str, str, bool]) -> dict[str, int | str]:
    """Worker function for parallel processing."""
    in_path, out_path, allow_ip = args
    return process_file(in_path, out_path, allow_ip)


def _transform_internal(
    input_path: str, output_path: str, allow_ip: bool, parallel: bool = True
) -> list[dict[str, int | str]]:
    """
    Internal transform helper handling file/directory inputs.
    
    Args:
        input_path: Input file or directory
        output_path: Output file or directory
        allow_ip: Whether to allow IP addresses in hostnames
        parallel: Use parallel processing for directories (default: True)
    """
    results: list[dict[str, int | str]] = []
    inp = Path(input_path)
    outp = Path(output_path)
    
    if inp.is_dir():
        outp.mkdir(parents=True, exist_ok=True)
        
        # Collect all files to process
        files_to_process = [
            (str(entry), str(outp / entry.name), allow_ip)
            for entry in utils.list_text_rule_files(inp)
        ]
        
        if not files_to_process:
            return results
        
        # Use parallel processing if enabled and multiple files
        if parallel and len(files_to_process) > 1:
            # Use all available CPU cores (no artificial cap)
            num_workers = min(mp.cpu_count(), len(files_to_process))
            with mp.Pool(processes=num_workers) as pool:
                results = pool.map(_process_file_worker, files_to_process)
        else:
            # Sequential processing (single file or parallel disabled)
            for in_path, out_path, allow_ip_flag in files_to_process:
                results.append(process_file(in_path, out_path, allow_ip_flag))
                
    elif inp.is_file():
        if outp.is_dir():
            out_file = outp / inp.name
        else:
            out_file = outp
            out_file.parent.mkdir(parents=True, exist_ok=True)
        results.append(process_file(str(inp), str(out_file), allow_ip))
    else:
        raise FileNotFoundError(f"Input path not found: {input_path}")
    return results


def transform(input_path: str, output_path: str) -> list[dict[str, int | str]]:
    """Default transform: allow IP hostnames (ValidateAllowIp semantics)."""
    return _transform_internal(input_path, output_path, allow_ip=True)


def transform_disallow_ip(input_path: str, output_path: str) -> list[dict[str, int | str]]:
    """Transform that disallows IP hostnames (parity/testing)."""
    return _transform_internal(input_path, output_path, allow_ip=False)


def _print_summary(stats_list: list[dict[str, int | str]]) -> None:
    total_in = sum(s["lines_in"] for s in stats_list)
    total_out = sum(s["lines_out"] for s in stats_list)
    total_removed = sum(s["removed_invalid"] for s in stats_list)
    total_eh = sum(s["removed_element_hiding"] for s in stats_list)
    total_badmod = sum(s["removed_bad_modifier"] for s in stats_list)
    total_invalid_host = sum(s["removed_invalid_host"] for s in stats_list)
    print(
        f"validate: files={len(stats_list)} lines_in={total_in} lines_out={total_out} "
        f"removed_invalid={total_removed} element_hiding={total_eh} bad_modifier={total_badmod} "
        f"invalid_host={total_invalid_host}"
    )


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m scripts.validate INPUT OUTPUT", file=sys.stderr)
        sys.exit(2)
    inp = sys.argv[1]
    out = sys.argv[2]
    try:
        res = transform(inp, out)
        _print_summary(res)
    except Exception as exc:
        print(f"ERROR in validate: {exc}", file=sys.stderr)
        sys.exit(1)
