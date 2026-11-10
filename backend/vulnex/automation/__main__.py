"""``python -m vulnex.automation``: work through the queued automation requests.

Environment:
  VULNEX_API_URL          the Vulnex backend, e.g. https://vulnex-1k5h.onrender.com
  VULNEX_AUTOMATION_KEY   the automation key the backend trusts
  AZL_TEST_TOKEN          a token that can push branches and open PRs in azurelinux-test
  VULNEX_AUTOMATION_GITHUB_USER  optional: the GitHub login PRs must be raised as (refuses any other)
  VULNEX_AI_*             optional, see ai.py (GITHUB_TOKEN works by default in GitHub Actions)
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import traceback
from pathlib import Path

import requests

from . import patching, pr
from .ai import build_chat
from .runner import CveJob, Deps, Job, Result, run_job


def scrub(text: str, *secrets: str) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return text


def make_deps(token: str, dry_run: bool) -> Deps:
    pr.assert_target_repo()
    remote = f"https://x-access-token:{token}@github.com/{pr.ALLOWED_REPO}.git"

    def checkout(branch: str, folder: str, dest: Path) -> Path:
        try:
            patching.run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--no-checkout", "--branch", branch, remote, str(dest)], dest.parent)
            pr.assert_remote(patching.run(["git", "remote", "get-url", "origin"], dest).stdout)
            patching.run(["git", "sparse-checkout", "set", f"SPECS/{folder}"], dest)
            patching.run(["git", "checkout", "-q", branch], dest)
        except patching.PatchError as error:
            raise patching.PatchError(scrub(str(error), token)) from None
        return dest

    def download(url: str, dest: Path) -> None:
        if not url.startswith("https://"):
            raise patching.PatchError(f"Refusing to download from {url}")
        with requests.get(url, stream=True, timeout=300, allow_redirects=True) as response:
            response.raise_for_status()
            with open(dest, "wb") as out:
                for chunk in response.iter_content(1 << 20):
                    out.write(chunk)

    def push(repo: Path, branch: str) -> None:
        pr.assert_head_branch(branch)
        pr.assert_remote(patching.run(["git", "remote", "get-url", "origin"], repo).stdout)
        try:
            patching.run(["git", "push", "origin", f"HEAD:refs/heads/{branch}"], repo)  # never forced
        except patching.PatchError as error:
            raise patching.PatchError(scrub(str(error), token)) from None

    def base_release(repo: Path, base: str, path: str) -> int | None:
        try:
            patching.run(["git", "fetch", "-q", "--depth", "1", "origin", base], repo)
            text = patching.run(["git", "show", f"FETCH_HEAD:{path}"], repo).stdout
            from . import specfile
            return specfile.release(text)
        except Exception:
            return None

    return Deps(checkout=checkout, download=download, push=push, base_release=base_release,
                github=pr.GitHub(token), chat=build_chat(), dry_run=dry_run,
                expected_login=os.environ.get("VULNEX_AUTOMATION_GITHUB_USER", ""))


class Api:
    def __init__(self, base: str, key: str):
        self.base, self.key = base.rstrip("/"), key

    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        response = requests.request(method, f"{self.base}/api{path}", json=body, headers={"X-VULNEX-Key": self.key}, timeout=90)
        response.raise_for_status()
        return response.json()


def to_job(data: dict) -> Job:
    return Job(
        id=data["id"], package_name=data["package_name"], spec_path=data["spec_path"],
        mode=data["mode"], pr_number=data.get("pr_number") or "",
        cves=[CveJob(**{k: c.get(k) or "" for k in ("cve_id", "severity", "description", "patch_link", "branch", "spec_path")}) for c in data["cves"]],
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="do everything except push and open the PR (the request is not reported)")
    args = parser.parse_args(argv)
    env = os.environ
    missing = [n for n in ("VULNEX_API_URL", "VULNEX_AUTOMATION_KEY", "AZL_TEST_TOKEN") if not env.get(n)]
    if missing:
        print("Missing environment: " + ", ".join(missing), file=sys.stderr)
        return 2
    token = env["AZL_TEST_TOKEN"]
    api = Api(env["VULNEX_API_URL"], env["VULNEX_AUTOMATION_KEY"])
    failures = 0
    while True:
        data = api.call("POST", "/automation/jobs/next").get("job")
        if not data:
            print("No queued automation requests.")
            return 1 if failures else 0
        job = to_job(data)
        print(f"== Request {job.id}: {job.package_name} ({len(job.cves)} CVE(s), {job.mode})")
        try:
            with tempfile.TemporaryDirectory() as work:
                result = run_job(job, make_deps(token, args.dry_run), Path(work))
        except Exception as error:  # report every failure; one bad request must not stop the queue
            traceback.print_exc()
            result = Result("failed", scrub(f"{type(error).__name__}: {error}", token))
        print(f"   {result.status}: {result.message} {result.pr_url}")
        if args.dry_run:
            continue
        api.call("POST", f"/automation/jobs/{job.id}/result", {
            "status": result.status, "message": result.message[:2000], "pr_url": result.pr_url,
            "pr_number": result.pr_number, "branch_name": result.branch,
            "fixed": [o.cve_id for o in result.outcomes if o.ok],
        })
        if result.pr_url:
            by_id = {c.cve_id: c for c in job.cves}
            for outcome in result.outcomes:
                if outcome.ok:  # 13. the same call as the "Set GitHub PR" action
                    cve = by_id[outcome.cve_id]
                    api.call("POST", "/triage/github-pr", {"cve_id": cve.cve_id, "branch": cve.branch, "spec_path": cve.spec_path, "number": result.pr_number, "url": result.pr_url})
        failures += result.status == "failed"


if __name__ == "__main__":
    sys.exit(main())
