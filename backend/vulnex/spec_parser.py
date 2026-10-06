"""Azure Linux ``.spec`` file parser.

Extracts exactly what a CVE scan needs from an RPM spec file:

* package identity (name / version / release / epoch)
* ``Source*`` entries, including tarball URLs and their Azure Linux blob-store
  mirror locations
* ``Patch*`` / ``.nopatch`` entries with the CVE identifiers they reference

Only *active* (uncommented) ``Patch`` directives count. Commented-out patches
are the single most common source of false "already patched" claims, so they are
deliberately ignored.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from .config import BLOB_STORE_BASE

__all__ = ["ParsedSpec", "SourceItem", "PatchItem", "parse_spec", "expand", "extract_cve_ids"]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_MACRO_RE = re.compile(r"%\{(!\?|\?)?([A-Za-z0-9_]+)(?::([^{}]*))?\}")
_FIELD_RE = re.compile(
    r"^(Name|Version|Release|Epoch|Summary|License|URL|Group|Vendor|Distribution)\s*:\s*(.*)$",
    re.IGNORECASE,
)
_PATCH_RE = re.compile(r"^Patch(\d*)\s*:\s*(.*)$", re.IGNORECASE)
_SOURCE_RE = re.compile(r"^Source(\d*)\s*:\s*(.*)$", re.IGNORECASE)
_DEFINE_RE = re.compile(r"^%(?:define|global)\s+([A-Za-z0-9_]+)\s*(.*)$")

_TARBALL_SUFFIXES = (
    ".tar.gz",
    ".tgz",
    ".tar.xz",
    ".txz",
    ".tar.bz2",
    ".tar.zst",
    ".tar.lz",
    ".tar.lzma",
    ".tar",
    ".zip",
)


def extract_cve_ids(text: str) -> list[str]:
    """Return unique, upper-cased CVE ids found in ``text``."""
    seen: dict[str, None] = {}
    for match in CVE_RE.findall(text or ""):
        seen.setdefault(match.upper(), None)
    return list(seen)


def expand(text: str, macros: dict[str, str], _depth: int = 0) -> str:
    """Expand RPM macros in ``text`` using a simple ``%{name}`` resolver.

    Handles ``%{name}``, ``%{?name}``, ``%{?name:body}`` and ``%{!?name:body}``.
    Unknown macros expand to the empty string, so ``11%{?dist}`` becomes ``11``.
    """
    if not text:
        return ""
    if _depth > 8:
        return text

    def repl(match: re.Match[str]) -> str:
        modifier = match.group(1)
        name = match.group(2)
        body = match.group(3)
        defined = name in macros
        if modifier == "!?":
            if body is not None and not defined:
                return expand(body, macros, _depth + 1)
            return ""
        if modifier == "?":
            if body is not None:
                return expand(body, macros, _depth + 1) if defined else ""
            return macros.get(name, "")
        if body is not None and not defined:
            return expand(body, macros, _depth + 1)
        return macros.get(name, "")

    resolved = _MACRO_RE.sub(repl, text)
    if resolved != text:
        return expand(resolved, macros, _depth + 1)
    return resolved


@dataclass
class SourceItem:
    """A ``Source*`` entry from a spec file."""

    tag: str
    raw: str
    url: str
    filename: str
    is_tarball: bool
    blob_url: str | None


@dataclass
class PatchItem:
    """A ``Patch*`` entry from a spec file."""

    tag: str
    raw: str
    filename: str
    cve_ids: list[str] = field(default_factory=list)
    is_nopatch: bool = False
    applied: bool = True
    comment: str = ""
    # Whether the referenced patch file actually exists in the repository tree.
    file_present: bool | None = None

    @property
    def status(self) -> str:
        if self.is_nopatch:
            return "not-affected"
        if self.file_present is False:
            return "missing-file"
        return "applied"


@dataclass
class ParsedSpec:
    """Structured representation of an Azure Linux package spec."""

    branch: str
    path: str  # e.g. SPECS/curl/curl.spec
    name: str
    version: str
    release: str
    epoch: int
    summary: str
    license: str
    url: str
    group: str
    sources: list[SourceItem]
    patches: list[PatchItem]
    macros: dict[str, str]
    raw_url: str = ""

    @property
    def evr(self) -> str:
        """Version-release string used for vulnerability range matching."""
        base = f"{self.version}"
        if self.release:
            base = f"{base}-{self.release}"
        return base

    @property
    def package_dir(self) -> str:
        return posixpath.dirname(self.path)

    @property
    def primary_source(self) -> SourceItem | None:
        for src in self.sources:
            if src.tag.lower() in ("source", "source0"):
                return src
        return self.sources[0] if self.sources else None

    def patch_cves(self) -> dict[str, PatchItem]:
        """Map of CVE id -> patch item for applied CVE patches."""
        out: dict[str, PatchItem] = {}
        for patch in self.patches:
            for cve in patch.cve_ids:
                out.setdefault(cve, patch)
        return out

    def nopatch_cves(self) -> dict[str, PatchItem]:
        out: dict[str, PatchItem] = {}
        for patch in self.patches:
            if patch.is_nopatch:
                for cve in patch.cve_ids:
                    out.setdefault(cve, patch)
        return out


def _is_tarball(filename: str) -> bool:
    lower = filename.lower()
    return lower.endswith(_TARBALL_SUFFIXES)


def _filename_from_url(url: str) -> str:
    if not url:
        return ""
    path = url.split("?", 1)[0].split("#", 1)[0]
    return posixpath.basename(path)


def parse_spec(
    text: str,
    branch: str,
    path: str,
    present_files: set[str] | None = None,
    raw_url: str = "",
) -> ParsedSpec:
    """Parse the contents of an RPM spec file into a :class:`ParsedSpec`."""
    raw_fields: dict[str, str] = {}
    macro_defs: dict[str, str] = {}
    raw_patches: list[tuple[str, str, str]] = []  # (tag, raw_value, comment)
    raw_sources: list[tuple[str, str]] = []  # (tag, raw_value)

    comment_buffer: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            comment_buffer = []
            continue
        if stripped.startswith("#"):
            content = stripped.lstrip("#").strip()
            # A commented-out directive (e.g. `# Patch4: CVE-...patch`) is not
            # descriptive text: never let its CVE leak onto the next patch.
            if not (_PATCH_RE.match(content) or _SOURCE_RE.match(content) or _FIELD_RE.match(content)):
                comment_buffer.append(content)
            continue

        m = _DEFINE_RE.match(stripped)
        if m:
            macro_defs[m.group(1)] = m.group(2).strip()
            comment_buffer = []
            continue

        m = _FIELD_RE.match(stripped)
        if m:
            raw_fields.setdefault(m.group(1).lower(), m.group(2).strip())
            comment_buffer = []
            continue

        m = _SOURCE_RE.match(stripped)
        if m:
            tag = "Source" + (m.group(1) or "0")
            raw_sources.append((tag, m.group(2).strip()))
            comment_buffer = []
            continue

        m = _PATCH_RE.match(stripped)
        if m:
            tag = "Patch" + (m.group(1) or "0")
            # Only CVE ids in genuine descriptive comments count as references.
            raw_patches.append((tag, m.group(2).strip(), "\n".join(comment_buffer)))
            comment_buffer = []
            continue

        # Any other directive ends the current comment block.
        if stripped.startswith("%"):
            comment_buffer = []

    # Build the macro table with the resolved core identity values.
    macros: dict[str, str] = dict(macro_defs)
    for key in ("name", "version", "release", "epoch"):
        if key in raw_fields:
            macros[key] = expand(raw_fields[key], macros)
    # Re-resolve identity once macros are known (version may use %{name}).
    for key in ("name", "version", "release", "epoch"):
        if key in raw_fields:
            macros[key] = expand(raw_fields[key], macros)

    name = macros.get("name", "")
    version = macros.get("version", "")
    release = macros.get("release", "")
    try:
        epoch = int(macros.get("epoch", "0") or 0)
    except ValueError:
        epoch = 0

    sources: list[SourceItem] = []
    for tag, raw in raw_sources:
        url = expand(raw, macros)
        filename = _filename_from_url(url)
        is_tar = _is_tarball(filename)
        blob_url = f"{BLOB_STORE_BASE}/{filename}" if is_tar else None
        sources.append(
            SourceItem(
                tag=tag,
                raw=raw,
                url=url,
                filename=filename,
                is_tarball=is_tar,
                blob_url=blob_url,
            )
        )

    patches: list[PatchItem] = []
    for tag, raw, comment in raw_patches:
        filename = expand(raw, macros)
        cves = extract_cve_ids(filename) + extract_cve_ids(comment)
        # De-duplicate while preserving order and forcing upper case.
        seen: dict[str, None] = {}
        for cve in cves:
            seen.setdefault(cve.upper(), None)
        present: bool | None = None
        if present_files is not None:
            rel = posixpath.join(posixpath.dirname(path), _filename_from_url(filename))
            present = rel in present_files
        patches.append(
            PatchItem(
                tag=tag,
                raw=raw,
                filename=filename,
                cve_ids=list(seen),
                is_nopatch=filename.lower().endswith(".nopatch"),
                applied=True,
                comment=comment,
                file_present=present,
            )
        )

    return ParsedSpec(
        branch=branch,
        path=path,
        name=name,
        version=version,
        release=release,
        epoch=epoch,
        summary=expand(raw_fields.get("summary", ""), macros),
        license=expand(raw_fields.get("license", ""), macros),
        url=raw_fields.get("url", "").strip(),
        group=raw_fields.get("group", "").strip(),
        sources=sources,
        patches=patches,
        macros=macros,
        raw_url=raw_url,
    )
