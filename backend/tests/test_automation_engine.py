"""The automation engine, run end to end against a local stand-in for azurelinux-test."""

import difflib
import io
import shutil
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from test_access import AUTO, FINDING, client, admin  # noqa: F401  (shared fixtures)

from vulnex import config
from vulnex.automation import patching, pr, specfile
from vulnex.automation.runner import CveJob, Deps, Job, JobError, build_body, patch_name, reference_url, run_job, upstream_patch_url

WHEN = datetime(2026, 11, 10, tzinfo=timezone.utc)
MAIN_C = "int a(void) { return 1; }\n\nint b(void) {\n    return 2;\n}\n\nint c(void) { return 3; }\n"

SPEC = """Name:           demo
Version:        1.0
Release:        3%{?dist}
Summary:        Demo
Source0:        https://example.org/%{name}-%{version}.tar.gz
Patch0:         existing.patch

%autosetup -p1

%changelog
* Mon Jan 05 2026 Someone <someone@example.org> - 1.0-3
- Older entry
"""


def _udiff(old: str, new: str, name="main.c") -> str:
    body = "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{name}", f"b/{name}"))
    return f"diff --git a/{name} b/{name}\n{body}"


def _tarball(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(f"demo-1.0/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


EXISTING = _udiff(MAIN_C, MAIN_C.replace("return 1", "return 10"))
AFTER_EXISTING = MAIN_C.replace("return 1", "return 10")
CLEAN = _udiff(AFTER_EXISTING, AFTER_EXISTING.replace("return 3", "return 33"))
# Written for a different version of the file, so its context is not there and it must be backported.
DIFFERENT = AFTER_EXISTING.replace("return 2;", "return 2; /* v2 */")
NEEDS_PORT = _udiff(DIFFERENT, DIFFERENT.replace("return 2; /* v2 */", "return 22; /* v2 */"))


def _git(path: Path, *args):
    subprocess.run(["git", *args], cwd=path, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(path)})


@pytest.fixture()
def world(tmp_path):
    origin = tmp_path / "origin"
    (origin / "SPECS/demo").mkdir(parents=True)
    (origin / "SPECS/demo/demo.spec").write_text(SPEC)
    (origin / "SPECS/demo/existing.patch").write_text(EXISTING)
    _git(origin, "init", "-q", "-b", "3.0-dev")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-q", "-m", "base")
    files = {"https://example.org/demo-1.0.tar.gz": _tarball({"main.c": MAIN_C}),
             "https://github.com/o/r/commit/aaaaaaa1.patch": CLEAN.encode(),
             "https://github.com/o/r/commit/bbbbbbb2.patch": NEEDS_PORT.encode()}
    pushed, prs, comments = [], [], []

    class FakeGitHub:
        def create_draft_pr(self, head, base, title, body):
            prs.append({"head": head, "base": base, "title": title, "body": body, "draft": True})
            return {"number": 7, "html_url": "https://github.com/akhila-dev5/azurelinux-test/pull/7"}

        def get_pull(self, number):
            return {"base": {"ref": "3.0-dev"}, "head": {"ref": "topic/demo/3.0/CVE-2026-0001"},
                    "html_url": f"https://github.com/akhila-dev5/azurelinux-test/pull/{number}"}

        def login(self):
            return "vulnex-sec"

        def comment(self, number, body):
            comments.append((number, body))

    def checkout(branch, folder, dest):
        shutil.copytree(origin, dest)
        _git(dest, "checkout", "-q", "-B", branch)
        return dest

    def download(url, dest):
        if url not in files:
            raise patching.PatchError(f"404 {url}")
        Path(dest).write_bytes(files[url])

    def deps(chat=None, **extra):
        return Deps(checkout=checkout, download=download, push=lambda repo, branch: pushed.append(branch),
                    base_release=lambda *a: 3, github=FakeGitHub(), chat=chat, now=lambda: WHEN, log=lambda m: None, **extra)

    return type("World", (), {"deps": staticmethod(deps), "pushed": pushed, "prs": prs, "comments": comments,
                              "work": tmp_path / "work"})


def job(*cves, mode="new_pr", pr_number=""):
    return Job(1, "demo", "SPECS/demo/demo.spec", mode, pr_number, list(cves))


CLEAN_CVE = dict(cve_id="CVE-2026-0001", severity="high", description="Overflow in c().", patch_link="https://github.com/o/r/commit/aaaaaaa1", branch="3.0", spec_path="SPECS/demo/demo.spec")
PORT_CVE = dict(cve_id="CVE-2026-0002", severity="medium", description="Bad b().", patch_link="https://github.com/o/r/commit/bbbbbbb2", branch="3.0", spec_path="SPECS/demo/demo.spec")


# -- spec editing -----------------------------------------------------------
def test_spec_edits_follow_the_changelog_pattern():
    spec, number = specfile.add_patch(SPEC, "CVE-2026-0001.patch")
    assert number == 1 and "Patch1:         CVE-2026-0001.patch" in spec
    spec, evr = specfile.bump_release(spec)
    assert evr == "1.0-4" and "Release:        4%{?dist}" in spec
    spec = specfile.add_changelog(spec, ["CVE-2026-0001", "CVE-2026-0002"], evr, WHEN)
    assert ("%changelog\n* Tue Nov 10 2026 Vulnex Security Servicing Account <vulnexsecurityautomation@gmail.com> - 1.0-4\n"
            "- Patch for CVE-2026-0001, CVE-2026-0002\n\n* Mon Jan 05 2026") in spec


def test_spec_helpers_read_sources_and_merge_changelog_lines():
    assert specfile.source0(SPEC) == "https://example.org/demo-1.0.tar.gz"
    assert specfile.sources(SPEC + "Source1: https://x.org/%{name}-extra.tar.gz\n")[1] == "https://x.org/demo-extra.tar.gz"
    spec = specfile.add_changelog(SPEC, ["CVE-1"], "1.0-4", WHEN)
    assert "- Patch for CVE-1, CVE-2\n" in specfile.merge_into_top_entry(spec, ["CVE-2"])


def test_patch_lines_for_specs_that_apply_patches_by_hand():
    spec = SPEC.replace("%autosetup -p1", "%setup -q\n%patch0 -p1")
    updated, _ = specfile.add_patch(spec, "CVE-2026-0001.patch")
    assert "%patch1 -p1" in updated


def test_upstream_links_become_raw_patch_urls():
    assert upstream_patch_url("https://github.com/o/r/commit/abcdef1") == "https://github.com/o/r/commit/abcdef1.patch"
    assert upstream_patch_url("https://github.com/o/r/pull/12") == "https://github.com/o/r/pull/12.patch"
    assert patch_name("https://github.com/o/r/commit/abcdef1234", "CVE-1") == "abcdef1234.patch"


FULL = "52ca1113d651127f89477a8763f86ab20f645e1d"


def test_reference_url_uses_the_full_commit_sha():
    mbox = f"From {FULL} Mon Sep 17 00:00:00 2001\nSubject: x\n"
    assert reference_url("https://github.com/o/r/commit/52ca111", mbox) == f"https://github.com/o/r/commit/{FULL}.patch"
    assert reference_url(f"https://github.com/o/r/commit/{FULL}.patch", mbox) == f"https://github.com/o/r/commit/{FULL}.patch"
    # no commit SHA to swap (a pull request): the link is used as it is
    assert reference_url("https://github.com/o/r/pull/12", mbox) == "https://github.com/o/r/pull/12.patch"
    assert reference_url("https://github.com/o/r/commit/52ca111", "no header") == "https://github.com/o/r/commit/52ca111.patch"


def test_the_cve_patch_names_its_upstream_source_under_the_subject(world):
    run_job(job(CveJob(**CLEAN_CVE)), world.deps(), world.work)
    text = (world.work / "repo/SPECS/demo/CVE-2026-0001.patch").read_text()
    lines = text.splitlines()
    subject = next(i for i, l in enumerate(lines) if l.startswith("Subject: [PATCH] Address CVE-2026-0001"))
    assert lines[subject + 1].strip() == ""
    assert lines[subject + 2] == "Upstream Patch Reference:   https://github.com/o/r/commit/aaaaaaa1.patch"
    assert lines[subject + 3] == "---"


# -- the guards -------------------------------------------------------------
def test_severity_decides_the_base_branch_and_names():
    assert pr.base_branch_for(["high"]) == pr.base_branch_for(["critical", "low"]) == "fasttrack/3.0"
    assert pr.base_branch_for(["medium", "low"]) == "3.0-dev"
    assert pr.highest_severity(["low", "critical", "high"]) == "critical"
    assert pr.branch_name("kured", ["CVE-2026-2", "CVE-2026-1"]) == "topic/kured/3.0/CVE-2026-1"
    assert pr.pr_title("kured", ["CVE-1", "CVE-2"], "high") == "[Vulnex-AutoPR] Patch kured for CVE-1, CVE-2 [HIGH]"


def test_only_azurelinux_test_is_accepted(monkeypatch):
    pr.assert_remote("https://github.com/akhila-dev5/azurelinux-test.git")
    pr.assert_remote("https://x-access-token:secret@github.com/akhila-dev5/azurelinux-test.git")
    for bad in ("https://github.com/microsoft/azurelinux.git", "https://github.com/akhila-dev5/vulnex",
                "https://github.com/akhila-dev5/azurelinux-test-evil", "https://evil.example/akhila-dev5/azurelinux-test"):
        with pytest.raises(pr.TargetRepoError):
            pr.assert_remote(bad)
    monkeypatch.setattr(config, "PATCH_TARGET_REPO", "microsoft/azurelinux")
    with pytest.raises(pr.TargetRepoError):
        pr.GitHub("token")


def test_automation_never_pushes_to_a_base_branch():
    for bad in ("3.0", "3.0-dev", "fasttrack/3.0", "main"):
        with pytest.raises(pr.TargetRepoError):
            pr.assert_head_branch(bad)
    pr.assert_head_branch("topic/demo/3.0/CVE-2026-0001")


class _User:
    def __init__(self, login, status=200):
        self.login, self.status = login, status

    def get(self, url, **kwargs):
        me = self

        class R:
            status_code = me.status

            def json(self):
                return {"login": me.login}
        return R()


def test_a_token_from_the_repo_owner_is_refused_so_prs_are_not_credited_to_a_person():
    with pytest.raises(pr.TargetRepoError, match="credited to that person"):
        pr.check_token_owner("t", "", _User("akhila-dev5"))
    assert pr.check_token_owner("t", "", _User("vulnex-sec")) == "vulnex-sec"


def test_a_token_must_belong_to_the_named_automation_account():
    assert pr.check_token_owner("t", "Vulnex-Sec", _User("vulnex-sec")) == "vulnex-sec"
    with pytest.raises(pr.TargetRepoError, match="belongs to 'someone'"):
        pr.check_token_owner("t", "vulnex-sec", _User("someone"))
    assert pr.check_token_owner("t", "akhila-dev5", _User("akhila-dev5")) == "akhila-dev5"  # deliberate choice
    with pytest.raises(pr.TargetRepoError, match="did not accept"):
        pr.check_token_owner("t", "", _User("x", status=401))


class _Session:
    def __init__(self, response):
        self.response, self.sent = response, []

    def request(self, method, url, **kwargs):
        self.sent.append((method, url, kwargs))
        outer = self

        class R:
            status_code = 201
            text = ""

            def json(self):
                return outer.response
        return R()


def _pull(repo="akhila-dev5/azurelinux-test"):
    return {"number": 7, "html_url": "x", "state": "open", "base": {"ref": "3.0-dev", "repo": {"full_name": repo}},
            "head": {"ref": "topic/demo/3.0/CVE-1", "repo": {"full_name": repo}}}


def test_github_client_only_talks_to_azurelinux_test_and_opens_drafts():
    session = _Session(_pull())
    pr.GitHub("t", session).create_draft_pr("topic/demo/3.0/CVE-1", "3.0-dev", "title", "body")
    method, url, kwargs = session.sent[0]
    assert url == "https://api.github.com/repos/akhila-dev5/azurelinux-test/pulls" and kwargs["json"]["draft"] is True
    with pytest.raises(pr.TargetRepoError):  # the release branch is never a target
        pr.GitHub("t", session).create_draft_pr("topic/demo/3.0/CVE-1", "3.0", "t", "b")
    with pytest.raises(pr.TargetRepoError):  # a response for another repository is not trusted
        pr.GitHub("t", _Session(_pull("microsoft/azurelinux"))).create_draft_pr("topic/demo/3.0/CVE-1", "3.0-dev", "t", "b")


# -- the whole job ----------------------------------------------------------
def test_clean_patch_goes_through_every_step(world):
    result = run_job(job(CveJob(**CLEAN_CVE)), world.deps(), world.work)
    assert result.status == "done" and result.base == "fasttrack/3.0"
    assert world.pushed == ["topic/demo/3.0/CVE-2026-0001"]
    created = world.prs[0]
    assert created["draft"] and created["base"] == "fasttrack/3.0"
    assert created["title"] == "[Vulnex-AutoPR] Patch demo for CVE-2026-0001 [HIGH]"
    assert "CVE-2026-0001 [HIGH]" in created["body"] and "applied cleanly" in created["body"]
    repo = world.work / "repo"
    patch = (repo / "SPECS/demo/CVE-2026-0001.patch").read_text()
    assert patch.startswith("From ") and "return 33" in patch and "Address CVE-2026-0001" in patch
    spec = (repo / "SPECS/demo/demo.spec").read_text()
    assert "Patch1:" in spec and "CVE-2026-0001.patch" in spec and "Release:        4%{?dist}" in spec
    assert "- Patch for CVE-2026-0001\n" in spec
    assert (world.work / "demo" / "aaaaaaa1.patch").exists()  # downloaded into the package-named folder


def test_a_patch_that_does_not_apply_is_backported_by_the_ai(world):
    def chat(messages):
        assert "Rejected hunks" in messages[-1]["content"]
        return ('```json\n{"edits":[{"file":"main.c","old":"    return 2;","new":"    return 22;"}],'
                '"explanation":"Code is older here."}\n```')

    result = run_job(job(CveJob(**PORT_CVE)), world.deps(chat=chat), world.work)
    assert result.status == "done" and result.base == "3.0-dev"
    assert "Backported" in world.prs[0]["body"] and "Code is older here." in world.prs[0]["body"]
    assert "return 22" in (world.work / "repo/SPECS/demo/CVE-2026-0002.patch").read_text()
    assert not list((world.work / "demo").rglob("*.rej"))


def test_without_an_ai_model_an_unclean_cve_is_skipped_not_faked(world):
    result = run_job(job(CveJob(**CLEAN_CVE), CveJob(**PORT_CVE)), world.deps(chat=None), world.work)
    assert result.status == "partial"
    assert "No AI model" in next(o.message for o in result.outcomes if not o.ok)
    assert "CVE-2026-0002" not in world.prs[0]["title"]


def test_mixed_severity_uses_fasttrack_and_lists_each_severity(world):
    chat = lambda m: '{"edits":[{"file":"main.c","old":"    return 2;","new":"    return 22;"}],"explanation":"e"}'  # noqa: E731
    result = run_job(job(CveJob(**PORT_CVE), CveJob(**CLEAN_CVE)), world.deps(chat=chat), world.work)
    assert result.status == "done" and world.prs[0]["base"] == "fasttrack/3.0"
    title, body = world.prs[0]["title"], world.prs[0]["body"]
    assert title == "[Vulnex-AutoPR] Patch demo for CVE-2026-0001, CVE-2026-0002 [HIGH]"
    assert "CVE-2026-0001 | HIGH" in body and "CVE-2026-0002 | MEDIUM" in body
    spec = (world.work / "repo/SPECS/demo/demo.spec").read_text()
    assert "- Patch for CVE-2026-0001, CVE-2026-0002\n" in spec and spec.count("Release:        4") == 1


def test_a_token_owned_by_the_wrong_github_account_is_refused(world):
    with pytest.raises(JobError, match="belongs to GitHub user 'vulnex-sec'"):
        run_job(job(CveJob(**CLEAN_CVE)), world.deps(expected_login="akhila-dev5"), world.work)
    assert not world.pushed and not world.prs


def test_the_expected_github_account_is_accepted(world):
    result = run_job(job(CveJob(**CLEAN_CVE)), world.deps(expected_login="Vulnex-Sec"), world.work)
    assert result.status == "done" and world.prs


def test_dry_run_changes_nothing_remote(world):
    result = run_job(job(CveJob(**CLEAN_CVE)), world.deps(dry_run=True), world.work)
    assert result.status == "done" and not world.pushed and not world.prs


def test_existing_pr_gets_a_commit_and_a_comment_not_a_new_pr(world):
    medium = {**PORT_CVE, "patch_link": "https://github.com/o/r/commit/aaaaaaa1"}
    result = run_job(job(CveJob(**medium), mode="existing_pr", pr_number="7"), world.deps(), world.work)
    assert result.status == "done" and result.pr_number == "7" and not world.prs
    assert world.pushed == ["topic/demo/3.0/CVE-2026-0001"] and world.comments[0][0] == 7


def test_existing_pr_on_the_wrong_base_is_refused(world):
    with pytest.raises(JobError, match="belong on fasttrack/3.0"):
        run_job(job(CveJob(**CLEAN_CVE), mode="existing_pr", pr_number="7"), world.deps(), world.work)
    assert not world.pushed


def test_the_apply_script_reports_a_broken_existing_patch(world, tmp_path):
    spec = tmp_path / "x.spec"
    spec.write_text("Patch0: bad.patch\n")
    (tmp_path / "bad.patch").write_text("--- a/nothing\n+++ b/nothing\n@@ -1 +1 @@\n-a\n+b\n")
    src = tmp_path / "src"
    src.mkdir()
    with pytest.raises(patching.PatchError, match="bad.patch"):
        patching.apply_existing(src, spec)


# -- the API side -----------------------------------------------------------
def test_worker_endpoints_need_the_automation_key(client, admin):  # noqa: F811
    assert client.post("/api/automation/jobs/next").status_code == 401
    assert client.post("/api/automation/jobs/next", headers=admin).status_code == 401
    assert client.post("/api/automation/jobs/next", headers=AUTO).json() == {"job": None}


def test_a_queued_request_becomes_a_job_and_its_result_is_recorded(client, admin):  # noqa: F811
    from test_claim_workflows import _sign_in

    client.post("/api/assignments", headers=admin, json={
        "cve_id": FINDING["cve_id"], "package_name": "demo", "assignee_email": config.AUTOMATION_EMAIL})
    client.post("/api/triage/patch", headers=admin, json={**FINDING, "final_verdict": "Patch Available", "patch_link": "https://github.com/o/r/commit/abcdef1"})
    body = {"package_name": "demo", "branch": FINDING["branch"], "spec_path": FINDING["spec_path"],
            "cve_ids": [FINDING["cve_id"]], "mode": "new_pr"}
    assert client.post("/api/automation/requests", headers=admin, json=body).status_code == 200
    # while it waits, the package cannot be queued twice
    assert client.post("/api/automation/requests", headers=admin, json=body).status_code == 409
    job = client.post("/api/automation/jobs/next", headers=AUTO).json()["job"]
    assert job["package_name"] == "demo" and job["cves"][0]["cve_id"] == FINDING["cve_id"]
    assert job["cves"][0]["patch_link"] == "https://github.com/o/r/commit/abcdef1"
    assert client.post("/api/automation/jobs/next", headers=AUTO).json() == {"job": None}  # taken
    done = client.post(f"/api/automation/jobs/{job['id']}/result", headers=AUTO, json={
        "status": "done", "pr_url": "https://github.com/akhila-dev5/azurelinux-test/pull/9", "pr_number": "9",
        "branch_name": "topic/demo/3.0/x"})
    assert done.json()["request"]["status"] == "done" and done.json()["request"]["pr_url"].endswith("/pull/9")
    # once the PR is set on the CVE, it leaves the Automation list
    client.post("/api/triage/github-pr", headers=AUTO, json={**FINDING, "number": "9", "url": "https://github.com/akhila-dev5/azurelinux-test/pull/9"})
    assert client.get("/api/automation", headers=admin).json()["packages"] == []
