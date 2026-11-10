"""Read and edit an RPM spec file: add a patch, bump the release, add a changelog entry.

Only the small set of edits the automation needs. Everything is plain text work so it can
be tested without rpm installed.
"""

from __future__ import annotations

import re
from datetime import datetime

AUTHOR_NAME = "Vulnex Security Servicing Account"
AUTHOR_EMAIL = "vulnexsecurityautomation@gmail.com"

_MACRO = re.compile(r"%\{(\??)(\w+)\}|%(\w+)")


def macros(spec: str) -> dict[str, str]:
    """Name, Version, Release and simple ``%global`` / ``%define`` values."""
    found: dict[str, str] = {}
    for line in spec.splitlines():
        m = re.match(r"^(Name|Version|Release|Epoch):\s*(\S.*?)\s*$", line)
        if m:
            found.setdefault(m.group(1).lower(), m.group(2))
            continue
        m = re.match(r"^%(?:global|define)\s+(\w+)\s+(.*?)\s*$", line)
        if m:
            found[m.group(1)] = m.group(2)
    return found


def expand(text: str, values: dict[str, str], depth: int = 0) -> str:
    """Replace ``%{name}`` / ``%name`` using ``values``; unknown macros are left alone."""

    def swap(match: re.Match) -> str:
        conditional, braced, bare = match.group(1), match.group(2), match.group(3)
        key = braced or bare
        if key in values:
            return values[key]
        return "" if conditional else match.group(0)

    out = _MACRO.sub(swap, text)
    if out != text and depth < 5:
        return expand(out, values, depth + 1)
    return out


def source0(spec: str) -> str:
    """The expanded Source0 (or Source) URL."""
    values = macros(spec)
    for line in spec.splitlines():
        m = re.match(r"^Source0?:\s*(\S+)", line)
        if m:
            return expand(m.group(1), values)
    raise ValueError("The spec file has no Source0 line")


def sources(spec: str) -> dict[int, str]:
    """Expanded ``SourceN`` values by number (a bare ``Source:`` is Source0)."""
    values = macros(spec)
    found: dict[int, str] = {}
    for m in re.finditer(r"^Source(\d*):\s*(\S+)", spec, re.MULTILINE):
        found.setdefault(int(m.group(1) or 0), expand(m.group(2), values))
    return found


def patch_entries(spec: str) -> list[tuple[int, str]]:
    """``[(number, filename)]`` for every active ``PatchN:`` line, in file order."""
    return [
        (int(m.group(1)), m.group(2))
        for m in re.finditer(r"^Patch(\d+):\s*(\S+)", spec, re.MULTILINE)
    ]


def strip_levels(spec: str) -> dict[int | None, int]:
    """The ``-pN`` for each ``%patchN`` line; ``None`` holds the ``%autosetup`` default."""
    levels: dict[int | None, int] = {}
    for m in re.finditer(r"^%autosetup\b([^\n]*)", spec, re.MULTILINE):
        p = re.search(r"-p(\d+)", m.group(1))
        levels[None] = int(p.group(1)) if p else 0
    for m in re.finditer(r"^%patch-?(\d+)\b([^\n]*)", spec, re.MULTILINE):
        p = re.search(r"-p(\d+)", m.group(2))
        levels[int(m.group(1))] = int(p.group(1)) if p else 0
    return levels


def add_patch(spec: str, filename: str) -> tuple[str, int]:
    """Add ``PatchN: filename`` (and a ``%patchN`` line for specs that apply patches by hand)."""
    entries = patch_entries(spec)
    number = max((n for n, _ in entries), default=-1) + 1
    lines = spec.split("\n")
    last_patch = max((i for i, l in enumerate(lines) if re.match(r"^Patch\d+:", l)), default=None)
    if last_patch is not None:
        gap = re.match(r"^Patch\d+:(\s*)", lines[last_patch]).group(1)
        total = len(f"Patch{entries[-1][0]}:") + len(gap)
        pad = " " * max(1, total - len(f"Patch{number}:"))
        lines.insert(last_patch + 1, f"Patch{number}:{pad}{filename}")
    else:
        last_source = max((i for i, l in enumerate(lines) if re.match(r"^Source\d*:", l)), default=None)
        if last_source is None:
            raise ValueError("The spec file has no Source line to add a Patch after")
        lines.insert(last_source + 1, f"Patch{number}:        {filename}")
    if not re.search(r"^%(autosetup|autopatch)\b", "\n".join(lines), re.MULTILINE):
        applied = [i for i, l in enumerate(lines) if re.match(r"^%patch-?\d+\b", l)]
        if applied:
            level = strip_levels(spec).get(entries[-1][0] if entries else None, 1) or 1
            lines.insert(applied[-1] + 1, f"%patch{number} -p{level}")
    return "\n".join(lines), number


def release(spec: str) -> int:
    m = re.search(r"^Release:\s*(\d+)", spec, re.MULTILINE)
    if not m:
        raise ValueError("The spec file has no numeric Release")
    return int(m.group(1))


def bump_release(spec: str) -> tuple[str, str]:
    """Increase the Release by one. Returns (new spec, ``version-release``)."""
    m = re.search(r"^(Release:\s*)(\d+)(.*)$", spec, re.MULTILINE)
    if not m:
        raise ValueError("The spec file has no numeric Release")
    new = int(m.group(2)) + 1
    spec = spec[: m.start()] + f"{m.group(1)}{new}{m.group(3)}" + spec[m.end():]
    return spec, f"{macros(spec).get('version', '')}-{new}"


def current_evr(spec: str) -> str:
    return f"{macros(spec).get('version', '')}-{release(spec)}"


def changelog_entry(cves: list[str], evr: str, when: datetime) -> str:
    return (
        f"* {when.strftime('%a %b %d %Y')} {AUTHOR_NAME} <{AUTHOR_EMAIL}> - {evr}\n"
        f"- Patch for {', '.join(cves)}\n"
    )


def add_changelog(spec: str, cves: list[str], evr: str, when: datetime) -> str:
    """Put a new entry directly under ``%changelog``."""
    entry = changelog_entry(cves, evr, when)
    m = re.search(r"^%changelog[^\n]*\n", spec, re.MULTILINE)
    if not m:
        return spec.rstrip("\n") + f"\n\n%changelog\n{entry}\n"
    return spec[: m.end()] + entry + "\n" + spec[m.end():]


def merge_into_top_entry(spec: str, cves: list[str]) -> str:
    """Add CVEs to the newest changelog entry's "Patch for ..." line (existing-PR mode)."""
    m = re.search(r"^(- Patch for )(.+)$", spec[spec.find("%changelog"):], re.MULTILINE)
    if not m:
        raise ValueError("No 'Patch for' line in the newest changelog entry")
    offset = spec.find("%changelog")
    have = [c.strip() for c in m.group(2).split(",")]
    merged = have + [c for c in cves if c not in have]
    start, end = offset + m.start(), offset + m.end()
    return spec[:start] + m.group(1) + ", ".join(merged) + spec[end:]
