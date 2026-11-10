"""Run one automation job: from the downloaded source to a draft PR in azurelinux-test."""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import requests

from . import patching, pr, specfile
from .ai import Chat
from .backport import backport

SEVERITY_RANK = pr.SEVERITY_ORDER


class JobError(RuntimeError):
    pass


@dataclass
class CveJob:
    cve_id: str
    severity: str = ""
    description: str = ""
    patch_link: str = ""
    branch: str = ""
    spec_path: str = ""


@dataclass
class Job:
    id: int
    package_name: str
    spec_path: str
    mode: str  # new_pr | existing_pr
    pr_number: str
    cves: list[CveJob]


@dataclass
class Outcome:
    cve_id: str
    severity: str
    ok: bool = False
    method: str = ""  # clean | backported
    explanation: str = ""
    message: str = ""
    upstream_patch: str = ""
    link: str = ""


@dataclass
class Result:
    status: str  # done | partial | failed
    message: str = ""
    pr_url: str = ""
    pr_number: str = ""
    branch: str = ""
    base: str = ""
    outcomes: list[Outcome] = field(default_factory=list)


@dataclass
class Deps:
    checkout: Callable[[str, str, Path], Path]  # (branch, spec dir name, destination) -> repo
    download: Callable[[str, Path], None]
    push: Callable[[Path, str], None]
    base_release: Callable[[Path, str, str], int | None]
    github: pr.GitHub | None = None
    chat: Chat | None = None
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    dry_run: bool = False
    expected_login: str = ""  # the GitHub account PRs must be raised as (empty: just report it)
    log: Callable[[str], None] = print


def upstream_patch_url(link: str) -> str:
    """The raw ``.patch`` for a commit or pull request link; other links are used as they are."""
    link = link.strip().split("#")[0].split("?")[0].rstrip("/")
    if link.endswith((".patch", ".diff")):
        return link
    if re.search(r"https://github\.com/[^/]+/[^/]+/(commit/[0-9a-f]{7,40}|pull/\d+)$", link):
        return link + ".patch"
    if re.search(r"/-/commit/[0-9a-f]{7,40}$", link):
        return link + ".patch"
    return link


def reference_url(link: str, patch_text: str) -> str:
    """The upstream ``.patch`` URL with the full 40-character commit SHA.

    A link may carry a short SHA. The downloaded patch starts "From <full sha> ...", so the
    short one is swapped for it. Links with no commit (a pull request) are kept as they are.
    """
    url = upstream_patch_url(link)
    head = re.match(r"From ([0-9a-f]{40})\b", patch_text)
    if head:
        url = re.sub(r"(?<=/)[0-9a-f]{7,40}(?=(\.patch|\.diff)?$)", head.group(1), url)
    return url


def patch_name(link: str, cve_id: str) -> str:
    sha = re.search(r"\b([0-9a-f]{7,40})\b", link or "")
    return f"{sha.group(1) if sha else cve_id}.patch"


def _ordered(cves: list[CveJob]) -> list[CveJob]:
    return sorted(cves, key=lambda c: (-SEVERITY_RANK.get(c.severity.lower(), 0), c.cve_id))


def _file_name(url: str) -> str:
    return Path(urlparse(url).path).name


def _git(repo: Path, *args: str) -> str:
    return patching.run(["git", *args], repo).stdout


def run_job(job: Job, deps: Deps, work: Path) -> Result:
    log = deps.log
    package = job.package_name
    folder = Path(job.spec_path).parent.name or package
    cves = _ordered(job.cves)
    if not cves:
        return Result("failed", "The request has no CVEs.")
    required_base = pr.base_branch_for([c.severity for c in cves])
    top = pr.highest_severity([c.severity for c in cves])

    # 1. Branch: a new topic branch from the base that the severity decides, or an existing PR's branch.
    if job.mode == "existing_pr":
        if deps.github is None:
            raise JobError("A GitHub client is needed to use an existing PR")
        existing = deps.github.get_pull(int(job.pr_number))
        base, branch = existing["base"]["ref"], existing["head"]["ref"]
        if base != required_base:
            raise JobError(f"PR #{job.pr_number} targets {base}, but these CVEs ({top}) belong on {required_base}.")
        repo = deps.checkout(branch, folder, work / "repo")
    else:
        base = required_base
        branch = pr.branch_name(package, [c.cve_id for c in cves])
        pr.assert_head_branch(branch)
        repo = deps.checkout(base, folder, work / "repo")
        _git(repo, "checkout", "-q", "-b", branch)
    log(f"Base {base}, branch {branch}, severity {top}")

    spec_dir = repo / "SPECS" / folder
    spec_file = spec_dir / f"{folder}.spec"
    if not spec_file.exists():
        found = sorted(spec_dir.glob("*.spec"))
        if not found:
            raise JobError(f"No spec file in SPECS/{folder} on {base}")
        spec_file = found[0]
    spec = spec_file.read_text()

    # 2. Source tarball (and Source1) plus each upstream patch, in a folder named after the package.
    pkgdir = work / package
    pkgdir.mkdir(parents=True, exist_ok=True)
    declared = specfile.sources(spec)
    url0 = specfile.source0(spec)
    tarball = pkgdir / _file_name(url0)
    log(f"Downloading {url0}")
    deps.download(url0, tarball)
    extra = None
    url1 = declared.get(1, "")
    if url1.startswith("http") and patching.is_archive(_file_name(url1)):
        extra = pkgdir / _file_name(url1)
        log(f"Downloading {url1}")
        deps.download(url1, extra)

    # 3. Untar Source0, enter it, and untar Source1 inside it.
    patching.untar(tarball, pkgdir)
    src = patching.source_dir_of(pkgdir)
    if extra:
        patching.untar(extra, src)

    # 4-7. Pristine commit, then everything the distribution already applies.
    patching.init_repo(src)
    report = patching.apply_existing(src, spec_file, patching.APPLY_SCRIPT)
    log(f"Existing patches applied: {len(report.ok)}")
    patching.commit_all(src, "In pace with azl-test")

    # 8-10. Each CVE's upstream patch, one after the other, backported by the AI model when it does not apply.
    outcomes: list[Outcome] = []
    for cve in cves:
        outcome = Outcome(cve.cve_id, cve.severity, link=cve.patch_link)
        outcomes.append(outcome)
        try:
            if (spec_dir / f"{cve.cve_id}.patch").exists():
                raise JobError("This package already has a patch with that name.")
            if not cve.patch_link:
                raise JobError("No upstream patch link is known for this CVE.")
            local = pkgdir / patch_name(cve.patch_link, cve.cve_id)
            deps.download(upstream_patch_url(cve.patch_link), local)
            outcome.upstream_patch = local.read_text(errors="replace")
            if "diff --git" not in outcome.upstream_patch and "\n--- " not in outcome.upstream_patch:
                raise JobError("The downloaded file is not a patch.")
            clean, rejects, output = patching.apply_upstream(src, local)
            if clean:
                outcome.method = "clean"
            else:
                log(f"{cve.cve_id}: does not apply cleanly ({len(rejects)} rejected file(s)); asking the AI model to backport")
                ported = backport(src, outcome.upstream_patch, rejects, deps.chat)
                if not ported.ok:
                    raise JobError("Backport failed: " + "; ".join(ported.problems))
                outcome.method, outcome.explanation = "backported", ported.explanation
            patching.make_patch(src, cve.cve_id, spec_dir, reference_url(cve.patch_link, outcome.upstream_patch))
            outcome.ok = True
        except (JobError, patching.PatchError, requests.RequestException) as error:
            outcome.message = str(error)
            log(f"{cve.cve_id}: skipped - {error}")
            patching.reset(src)

    done = [o for o in outcomes if o.ok]
    if not done:
        return Result("failed", "No CVE could be patched: " + "; ".join(f"{o.cve_id}: {o.message}" for o in outcomes),
                      branch=branch, base=base, outcomes=outcomes)

    # 11. Patch entries, release bump and changelog.
    ids = [o.cve_id for o in done]
    for cve_id in ids:
        spec, _ = specfile.add_patch(spec, f"{cve_id}.patch")
    when = deps.now()
    already = job.mode == "existing_pr" and (deps.base_release(repo, base, f"SPECS/{folder}/{spec_file.name}") or 0) < specfile.release(spec)
    if already:
        spec = specfile.merge_into_top_entry(spec, ids)
    else:
        spec, evr = specfile.bump_release(spec)
        spec = specfile.add_changelog(spec, ids, evr, when)
    spec_file.write_text(spec)
    _git(repo, "add", "--", f"SPECS/{folder}")
    _git(repo, "commit", "-q", "-m", f"Patch {package} for {', '.join(ids)}")

    status = "done" if len(done) == len(outcomes) else "partial"
    notes = "" if status == "done" else " Skipped: " + "; ".join(f"{o.cve_id} ({o.message})" for o in outcomes if not o.ok)
    if deps.dry_run:
        return Result(status, "Dry run: nothing was pushed." + notes, branch=branch, base=base, outcomes=outcomes)

    # 12. Push the topic branch and raise a draft PR, only in azurelinux-test.
    if deps.github is None:
        raise JobError("A GitHub client is needed to raise the PR")
    actor = deps.github.login()
    if deps.expected_login and actor.lower() != deps.expected_login.lower():
        raise JobError(
            f"The token belongs to GitHub user {actor!r}, but PRs must be raised as {deps.expected_login!r}. "
            "Create AZL_TEST_TOKEN while signed in as that account."
        )
    log(f"Raising the PR as GitHub user {actor}")
    deps.push(repo, branch)
    texts = {c.cve_id: c.description for c in cves}
    if job.mode == "existing_pr":
        deps.github.comment(int(job.pr_number), f"Vulnex added fixes for {', '.join(ids)} to this PR.\n\n" + build_body(package, base, outcomes, deps.chat, texts))
        number, url = job.pr_number, existing["html_url"]
    else:
        created = deps.github.create_draft_pr(branch, base, pr.pr_title(package, ids, pr.highest_severity([o.severity for o in done])), build_body(package, base, outcomes, deps.chat, texts))
        number, url = str(created["number"]), created["html_url"]
    return Result(status, f"Draft PR raised.{notes}", url, number, branch, base, outcomes)


def _explain(outcome: Outcome, description: str, chat: Chat | None) -> str:
    fallback = (description or "No description is available.").strip()
    if chat is None:
        return fallback + f"\n\nUpstream fix: {outcome.link}"
    prompt = (
        f"CVE: {outcome.cve_id} (severity {outcome.severity})\nDescription: {description}\n\n"
        f"Upstream patch:\n{outcome.upstream_patch[:12000]}\n\n"
        "In 4-6 plain sentences for a reviewer: say what this vulnerability is, then how the upstream "
        "patch fixes it. No headings, no lists."
    )
    try:
        return chat([{"role": "user", "content": prompt}]).strip() or fallback
    except Exception:  # an explanation must never stop the PR being raised
        return fallback + f"\n\nUpstream fix: {outcome.link}"


def build_body(package: str, base: str, outcomes: list[Outcome], chat: Chat | None, descriptions: dict[str, str] | None = None) -> str:
    descriptions = descriptions or {}
    done = [o for o in outcomes if o.ok]
    rows = "\n".join(f"| {o.cve_id} | {o.severity.upper() or 'UNKNOWN'} | {'Backported' if o.method == 'backported' else 'Upstream patch applied cleanly'} |" for o in done)
    parts = [
        f"Draft PR raised automatically by Vulnex for `{package}` against `{base}`.",
        "| CVE | Severity | How it was fixed |\n|---|---|---|\n" + rows,
    ]
    for o in done:
        text = _explain(o, descriptions.get(o.cve_id, ""), chat)
        section = f"### {o.cve_id} [{o.severity.upper() or 'UNKNOWN'}]\n{text}\n\nUpstream fix: {o.link}"
        if o.method == "backported":
            section += "\n\n**Backported.** The upstream patch did not apply to this version, so an AI model adapted it. " + (o.explanation or "") + "\nPlease review this change carefully."
        parts.append(section)
    skipped = [o for o in outcomes if not o.ok]
    if skipped:
        parts.append("### Not included\n" + "\n".join(f"- {o.cve_id}: {o.message}" for o in skipped))
    return "\n\n".join(parts)
