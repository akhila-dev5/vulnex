"""RPM version comparison.

A dependency-free port of RPM's ``rpmvercmp`` (``lib/rpmvercmp.c``) plus helpers
to compare full ``epoch:version-release`` (EVR) strings. This is what lets
VULNEX decide — from the vulnerability's ``introduced``/``fixed`` events — whether
a spec's version is genuinely inside an affected range instead of relying on
fuzzy keyword matching.

The tilde (``~``) and caret (``^``) separators are handled exactly as RPM does:
``1.0~rc1 < 1.0`` and ``1.0^git1 > 1.0``.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "rpmvercmp",
    "compare_evr",
    "split_evr",
    "EVR",
]


@dataclass(frozen=True)
class EVR:
    """A parsed epoch:version-release triple."""

    epoch: int
    version: str
    release: str


def split_evr(value: str) -> EVR:
    """Split an ``[epoch:]version[-release]`` string into its parts.

    Release is split on the *last* hyphen, matching RPM semantics, so
    ``1.2.3-4-5`` becomes version ``1.2.3-4`` and release ``5``.
    """
    value = (value or "").strip()
    epoch = 0
    if ":" in value:
        head, _, rest = value.partition(":")
        if head.isdigit():
            epoch = int(head)
            value = rest
    version, sep, release = value.rpartition("-")
    if not sep:
        return EVR(epoch, value, "")
    # Guard against versions like "1.2-" where the split is meaningless.
    if not version:
        return EVR(epoch, value, "")
    return EVR(epoch, version, release)


def rpmvercmp(a: str, b: str) -> int:
    """Compare two RPM version strings.

    Returns ``-1`` if ``a < b``, ``0`` if equal, ``1`` if ``a > b``.
    """
    a = a or ""
    b = b or ""
    if a == b:
        return 0

    i = j = 0
    la, lb = len(a), len(b)

    while i < la or j < lb:
        # Skip separators (anything that is not alphanumeric, '~' or '^').
        while i < la and not a[i].isalnum() and a[i] not in "~^":
            i += 1
        while j < lb and not b[j].isalnum() and b[j] not in "~^":
            j += 1

        # Tilde sorts before everything, including the end of string.
        if (i < la and a[i] == "~") or (j < lb and b[j] == "~"):
            if not (i < la and a[i] == "~"):
                return 1
            if not (j < lb and b[j] == "~"):
                return -1
            i += 1
            j += 1
            continue

        # Caret sorts after the base version but before any added segment.
        if (i < la and a[i] == "^") or (j < lb and b[j] == "^"):
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue

        # If either side ran out, we are done with the segment loop.
        if not (i < la and j < lb):
            break

        # The segment type is decided by the first string's next character.
        isnum = a[i].isdigit()
        seg_start_a = i
        if isnum:
            while i < la and a[i].isdigit():
                i += 1
        else:
            while i < la and a[i].isalpha():
                i += 1
        seg_a = a[seg_start_a:i]

        seg_start_b = j
        if isnum:
            if j < lb and b[j].isdigit():
                while j < lb and b[j].isdigit():
                    j += 1
        else:
            while j < lb and b[j].isalpha():
                j += 1
        seg_b = b[seg_start_b:j]

        # Different segment types: numeric is always newer than alpha.
        if seg_b == "":
            return 1 if isnum else -1

        if isnum:
            seg_a = seg_a.lstrip("0")
            seg_b = seg_b.lstrip("0")
            if len(seg_a) > len(seg_b):
                return 1
            if len(seg_b) > len(seg_a):
                return -1

        if seg_a != seg_b:
            return -1 if seg_a < seg_b else 1

    if i >= la and j >= lb:
        return 0
    if i >= la:
        return -1
    return 1


def compare_evr(a: str, b: str) -> int:
    """Compare two EVR strings (epoch, then version, then release)."""
    ea = split_evr(a)
    eb = split_evr(b)
    if ea.epoch != eb.epoch:
        return -1 if ea.epoch < eb.epoch else 1
    rc = rpmvercmp(ea.version, eb.version)
    if rc:
        return rc
    return rpmvercmp(ea.release, eb.release)
