"""Steps 3 to 9 of the patching process, done on a source directory with git and patch."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import specfile

APPLY_SCRIPT = Path(__file__).with_name("apply_patches.sh")
GIT_ENV = {
    "GIT_AUTHOR_NAME": specfile.AUTHOR_NAME,
    "GIT_AUTHOR_EMAIL": specfile.AUTHOR_EMAIL,
    "GIT_COMMITTER_NAME": specfile.AUTHOR_NAME,
    "GIT_COMMITTER_EMAIL": specfile.AUTHOR_EMAIL,
}
ARCHIVE = re.compile(r"\.(tar(\.\w+)?|tgz|tbz2?|txz|zip)$", re.IGNORECASE)


class PatchError(RuntimeError):
    pass


def run(cmd: list[str], cwd: Path, check: bool = True, stdin=subprocess.DEVNULL, text: str | None = None):
    """Run a command with no terminal input (the apply script must never wait for a person)."""
    result = subprocess.run(
        cmd, cwd=cwd, env={**os.environ, **GIT_ENV, "GIT_TERMINAL_PROMPT": "0"},
        input=text, stdin=None if text is not None else stdin,
        capture_output=True, text=True,
    )
    if check and result.returncode != 0:
        raise PatchError(f"{' '.join(cmd[:3])} failed: {(result.stderr or result.stdout).strip()[-800:]}")
    return result


def is_archive(name: str) -> bool:
    return bool(ARCHIVE.search(name))


def untar(archive: Path, into: Path) -> None:
    into.mkdir(parents=True, exist_ok=True)
    if archive.suffix.lower() == ".zip":
        run(["unzip", "-q", "-o", str(archive), "-d", str(into)], into)
    else:
        run(["tar", "-xf", str(archive), "-C", str(into)], into)


def source_dir_of(extracted: Path) -> Path:
    """The single top-level directory a source tarball unpacks to."""
    folders = [p for p in extracted.iterdir() if p.is_dir()]
    if len(folders) != 1:
        raise PatchError(f"Expected one source directory in the tarball, found {len(folders)}")
    return folders[0]


def init_repo(src: Path) -> None:
    """Steps 4 and 5: drop .gitignore and commit the pristine source."""
    (src / ".gitignore").unlink(missing_ok=True)
    run(["git", "init", "-q"], src)
    run(["git", "add", "-A"], src)  # a fresh repo has nothing tracked, so `commit -a` alone would commit nothing
    run(["git", "commit", "-q", "-m", "Initial commit"], src)


@dataclass
class ApplyReport:
    ok: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    output: str = ""


def parse_summary(output: str) -> ApplyReport:
    """Read the lists printed at the end of apply_patches.sh."""
    report = ApplyReport(output=output)
    section = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Successfully applied patches"):
            section = report.ok
        elif line.startswith("Failed patches"):
            section = report.failed
        elif section is not None and line and line != "None" and not line.startswith("="):
            section.append(line)
    return report


def apply_existing(src: Path, spec_file: Path, script: Path = APPLY_SCRIPT) -> ApplyReport:
    """Step 6: apply every patch the spec already lists, with the team's own script.

    The script asks a question when a patch fails; with no terminal it exits at that point,
    so a failed patch is read from its summary and stops the job.
    """
    result = run(["bash", str(script), str(spec_file), str(src)], src, check=False)
    report = parse_summary(result.stdout + result.stderr)
    if result.returncode != 0 or report.failed:
        raise PatchError("Existing patches do not apply cleanly: " + ", ".join(report.failed or ["see log"]))
    return report


def commit_all(src: Path, message: str) -> None:
    """Step 7: record the state the distribution ships today."""
    run(["git", "add", "-A"], src)
    run(["git", "commit", "-q", "--allow-empty", "-m", message], src)


def apply_upstream(src: Path, patch_file: Path) -> tuple[bool, list[Path], str]:
    """Step 8. Returns (applied cleanly, .rej files, output)."""
    result = run(["patch", "-p1", "--fuzz=0", "-i", str(patch_file)], src, check=False)
    rejects = sorted(p for p in src.rglob("*.rej") if ".git" not in p.parts)
    return result.returncode == 0 and not rejects, rejects, result.stdout + result.stderr


def reset(src: Path) -> None:
    run(["git", "reset", "-q", "--hard"], src)
    run(["git", "clean", "-fdq"], src)


def make_patch(src: Path, cve_id: str, dest: Path) -> Path:
    """Step 9: commit the change (no .orig or .rej) and write CVE-xxxx-yyyy.patch."""
    status = run(["git", "status", "--porcelain", "-z", "--untracked-files=all"], src).stdout
    paths = []
    for entry in status.split("\0"):
        if len(entry) > 3:
            path = entry[3:]
            if not path.endswith((".orig", ".rej")):
                paths.append(path)
    if not paths:
        raise PatchError(f"{cve_id}: the patch changed nothing")
    run(["git", "add", "--", *paths], src)
    run(["git", "commit", "-q", "-m", f"Address {cve_id}"], src)
    for leftover in [*src.rglob("*.orig"), *src.rglob("*.rej")]:
        if ".git" not in leftover.parts:
            leftover.unlink()
    patch = run(["git", "format-patch", "-1", "HEAD", "--stdout"], src).stdout
    out = dest / f"{cve_id}.patch"
    out.write_text(patch)
    return out
