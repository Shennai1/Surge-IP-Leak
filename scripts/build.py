#!/usr/bin/env python3
"""Build a deduplicated Surge rule set from the configured upstream lists."""

from __future__ import annotations

import argparse
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


V2FLY_DATA_BASE = (
    "https://raw.githubusercontent.com/v2fly/"
    "domain-list-community/master/data/"
)
V2FLY_ROOTS = ("category-ip-geo-detect", "test-ipv6")
EXTERNAL_SOURCES = (
    "https://raw.githubusercontent.com/iab0x00/ProxyRules/main/Rule/IPCheck.txt",
    # Deliberately revision-free: this URL always follows the latest Gist revision.
    "https://gist.githubusercontent.com/zzerding/"
    "2708745eda41024b366100f6896d0067/raw/ip-test",
)
OUTPUT = Path("rules/IPLeak.list")
USER_AGENT = "Surge-IP-Leak/1.0 (+https://github.com/Shennai1/Surge-IP-Leak)"
LIST_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")


@dataclass(frozen=True)
class Rule:
    kind: str
    domain: str
    attrs: frozenset[str] = frozenset()


def fetch(url: str, attempts: int = 3) -> str:
    """Fetch UTF-8 text with a small retry window for transient upstream errors."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read().decode("utf-8-sig")
        except (urllib.error.URLError, TimeoutError, UnicodeDecodeError):
            if attempt == attempts:
                raise
            time.sleep(2 ** (attempt - 1))
    raise AssertionError("unreachable")


def normalize_domain(value: str) -> str | None:
    """Lowercase a hostname, remove a trailing dot and convert Unicode to IDNA."""
    value = value.strip().strip("'\"")
    if "://" in value:
        value = urlsplit(value).hostname or ""
    value = value.removeprefix("+.").removeprefix("*.").lstrip(".")
    value = value.rstrip(".").lower()
    if not value or any(char.isspace() for char in value) or "/" in value:
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if (
        len(value) > 253
        or "." not in value
        or any(not label or len(label) > 63 for label in value.split("."))
    ):
        return None
    return value


def parse_v2fly_rule(line: str) -> Rule | None:
    """Parse a v2fly domain/full rule while retaining its attributes."""
    parts = line.split()
    if not parts:
        return None
    entry = parts[0]
    attrs = frozenset(token[1:] for token in parts[1:] if token.startswith("@"))

    if ":" in entry:
        prefix, value = entry.split(":", 1)
        prefix = prefix.lower()
    else:
        prefix, value = "domain", entry

    if prefix == "full":
        kind = "DOMAIN"
    elif prefix == "domain":
        kind = "DOMAIN-SUFFIX"
    elif prefix in {"keyword", "regexp", "include"}:
        return None
    else:
        return None

    domain = normalize_domain(value)
    return Rule(kind, domain, attrs) if domain else None


class V2FlyResolver:
    """Resolve v2fly includes recursively, including attribute selectors."""

    def __init__(self) -> None:
        self._memo: dict[str, tuple[Rule, ...]] = {}

    def resolve(self, name: str, stack: tuple[str, ...] = ()) -> tuple[Rule, ...]:
        if name in self._memo:
            return self._memo[name]
        if not LIST_NAME_RE.fullmatch(name):
            raise ValueError(f"invalid v2fly list name: {name!r}")
        if name in stack:
            chain = " -> ".join((*stack, name))
            raise ValueError(f"cyclic v2fly include: {chain}")

        text = fetch(V2FLY_DATA_BASE + name)
        rules: list[Rule] = []
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue

            parts = line.split()
            entry = parts[0]
            if entry.lower().startswith("include:"):
                included_name = entry.split(":", 1)[1]
                positive = {
                    token[1:]
                    for token in parts[1:]
                    if token.startswith("@") and not token.startswith("@-")
                }
                negative = {
                    token[2:] for token in parts[1:] if token.startswith("@-")
                }
                included = self.resolve(included_name, (*stack, name))
                rules.extend(
                    rule
                    for rule in included
                    if positive.issubset(rule.attrs) and rule.attrs.isdisjoint(negative)
                )
                continue

            rule = parse_v2fly_rule(line)
            if rule:
                rules.append(rule)

        result = tuple(rules)
        self._memo[name] = result
        return result


def parse_external(text: str) -> list[Rule]:
    """Parse Surge-style and plain-domain upstream lists."""
    rules: list[Rule] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line in {"payload:", "payload"}:
            continue
        if line.startswith("-"):
            line = line[1:].strip().strip("'\"")

        kind = "DOMAIN-SUFFIX"
        value = line.split()[0]
        if "," in line:
            fields = [field.strip() for field in line.split(",")]
            rule_type = fields[0].upper()
            if len(fields) < 2:
                continue
            if rule_type in {"DOMAIN", "HOST"}:
                kind = "DOMAIN"
            elif rule_type in {"DOMAIN-SUFFIX", "HOST-SUFFIX"}:
                kind = "DOMAIN-SUFFIX"
            else:
                continue
            value = fields[1]
        elif ":" in value and "://" not in value:
            prefix, candidate = value.split(":", 1)
            if prefix.lower() == "full":
                kind, value = "DOMAIN", candidate
            elif prefix.lower() == "domain":
                kind, value = "DOMAIN-SUFFIX", candidate
            elif prefix.lower() in {"keyword", "regexp", "include"}:
                continue

        domain = normalize_domain(value)
        if domain:
            rules.append(Rule(kind, domain))
    return rules


def suffix_covers(domain: str, suffixes: set[str]) -> bool:
    labels = domain.split(".")
    return any(".".join(labels[index:]) in suffixes for index in range(len(labels)))


def semantic_deduplicate(rules: list[Rule]) -> tuple[list[str], list[str]]:
    """Remove exact duplicates and rules covered by a parent suffix."""
    suffix_candidates = {rule.domain for rule in rules if rule.kind == "DOMAIN-SUFFIX"}
    exact_candidates = {rule.domain for rule in rules if rule.kind == "DOMAIN"}

    kept_suffixes: set[str] = set()
    for domain in sorted(suffix_candidates, key=lambda item: (item.count("."), item)):
        if not suffix_covers(domain, kept_suffixes):
            kept_suffixes.add(domain)

    kept_domains = {
        domain for domain in exact_candidates if not suffix_covers(domain, kept_suffixes)
    }
    return sorted(kept_domains), sorted(kept_suffixes)


def render(domains: list[str], suffixes: list[str]) -> str:
    total = len(domains) + len(suffixes)
    header = [
        "# Surge IP / DNS / IPv6 leak detection rules",
        "# Generated by scripts/build.py; do not edit manually.",
        f"# Rules: {total} (DOMAIN: {len(domains)}, DOMAIN-SUFFIX: {len(suffixes)})",
        "# Sources:",
        "# - v2fly/domain-list-community: category-ip-geo-detect (includes resolved)",
        "# - v2fly/domain-list-community: test-ipv6",
        "# - iab0x00/ProxyRules: Rule/IPCheck.txt",
        "# - zzerding Gist 2708745eda41024b366100f6896d0067: latest ip-test",
        "",
    ]
    body = [*(f"DOMAIN,{domain}" for domain in domains)]
    if domains and suffixes:
        body.append("")
    body.extend(f"DOMAIN-SUFFIX,{domain}" for domain in suffixes)
    return "\n".join((*header, *body, ""))


def build() -> str:
    resolver = V2FlyResolver()
    rules: list[Rule] = []
    for name in V2FLY_ROOTS:
        rules.extend(resolver.resolve(name))
    for url in EXTERNAL_SOURCES:
        rules.extend(parse_external(fetch(url)))

    domains, suffixes = semantic_deduplicate(rules)
    if len(domains) + len(suffixes) < 100:
        raise RuntimeError("refusing to write an unexpectedly small rule set")
    return render(domains, suffixes)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()

    content = build()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(content, encoding="utf-8", newline="\n")
    print(f"Wrote {args.output} ({content.count(chr(10))} lines)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"build failed: {error}", file=sys.stderr)
        raise
