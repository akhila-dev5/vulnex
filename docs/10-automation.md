# Automation: from a ticked CVE to a draft PR

The **Automation** page lists the CVEs held by `vulnexsecurityautomation@gmail.com` whose patch verdict is *Patch Available*, one card per package. **Automate** queues the ticked CVEs. A worker then patches them and raises **one draft PR per package** in `akhila-dev5/azurelinux-test`.

This is the development side. Scanning stays on the production branch `3.0`; fixes go to `fasttrack/3.0` and `3.0-dev`.

## The flow

```
Automate button -> automation_requests (queued) -> GitHub Actions "Vulnex automation"
   -> python -m vulnex.automation -> draft PR in azurelinux-test -> "Set GitHub PR" on each CVE
```

1. **Pick the base branch.** Highest severity wins: High or Critical go to `fasttrack/3.0`, Medium or Low to `3.0-dev`. A mixed package goes to `fasttrack/3.0`. The topic branch is `topic/<package>/3.0/<one CVE>`.
2. **Download** Source0 (and Source1 if the spec has one) and each upstream `.patch`, into a folder named after the package.
3. **Untar** Source0 and enter it; untar Source1 inside it.
4. Remove `.gitignore`, then `git init` and an "Initial commit". (The commit uses `git add -A` first, because a fresh repo has nothing tracked and `commit -a` alone would commit nothing.)
5. **Apply the existing patches** with `backend/vulnex/automation/apply_patches.sh`, then commit "In pace with azl-test". The script asks a question on failure; the worker gives it no terminal and reads its summary, so a failing existing patch stops the job.
6. **Apply each upstream patch**: `patch -p1 --fuzz=0`. If it applies with no `.rej`, the change is committed (no `.orig` or `.rej`) as "Address CVE-xxxx-yyyy" and `git format-patch -1` writes `CVE-xxxx-yyyy.patch`. Under the subject the patch carries `Upstream Patch Reference:   <upstream URL with the full commit SHA>.patch` (a short SHA in the link is replaced by the full one from the downloaded patch).
7. **If it does not apply**, an AI model backports it (see below), and the patch is made the same way.
8. **Edit the spec**: add `PatchN`, bump the Release, add a changelog entry:
   ```
   * Tue Nov 10 2026 Vulnex Security Servicing Account <vulnexsecurityautomation@gmail.com> - 1.9.0-2
   - Patch for CVE1, CVE2
   ```
9. **Raise a draft PR** titled `[Vulnex-AutoPR] Patch <pkg> for CVE1, CVE2 [SEVERITY]`. The body explains each CVE, how the upstream patch fixes it, each CVE's severity, and for backports how it was adapted.
10. **Set GitHub PR**: the worker calls the same API as the Set GitHub PR action for each fixed CVE, which links the PR in Vulnex and marks the CVE in progress.

A CVE that cannot be patched is skipped and named in the PR body and the request message (status `partial`); if none can be, the request is `failed` and no PR is raised.

## "Commit to an existing PR"

The pop-up can instead add the fixes to an open PR. The PR must be in azurelinux-test, open, on a `topic/` branch, and target the same base the severity requires. The worker pushes a commit to that branch and comments on the PR. If the PR already bumped the Release, the CVEs are added to its changelog line instead of bumping again.

## The AI backport

A model never edits freely. For each file with a `.rej` it gets the upstream patch, the current file and the rejected hunks, and answers with exact "find this text, replace with that" edits. An edit is only made if the text is found exactly once and the file had a `.rej`. It retries up to three times with the error fed back. Backported PRs say so and ask for careful review.

The default is **GitHub Models** (free; the workflow's own `GITHUB_TOKEN` works, model `openai/gpt-4.1`). Any OpenAI-compatible API works by setting `VULNEX_AI_BASE_URL`, `VULNEX_AI_MODEL` and the secret `VULNEX_AI_API_KEY` (for example Groq, OpenRouter's free models or Gemini's compatible endpoint). With no key at all, clean patches still work and a CVE that needs a backport is skipped.

## Safety: only azurelinux-test

- The repository name is a constant in `automation/pr.py`, not a setting. If `VULNEX_PATCH_TARGET_REPO` differs, the worker refuses to start.
- Every GitHub URL is built from that constant. No function accepts a repository or URL from outside.
- Git remotes are checked before cloning and before pushing; GitHub's answer is checked to be for azurelinux-test.
- PRs are always **drafts**, only against `fasttrack/3.0` or `3.0-dev`, **never** `3.0`.
- It only pushes to `topic/*` branches, never forces, and never pushes to a base branch.
- Tokens are scrubbed from error messages.

## Setup

Repository **Settings > Secrets and variables > Actions** in the vulnex repo:

| Name | Kind | What |
|---|---|---|
| `AZL_TEST_TOKEN` | secret | A token **created while signed in as the automation GitHub account** (see below) that can push branches and open PRs in azurelinux-test |
| `VULNEX_AUTOMATION_GITHUB_LOGIN` | variable | The automation account's GitHub username. The worker refuses a token that belongs to anyone else |
| `VULNEX_AUTOMATION_KEY` | secret | Same value as `VULNEX_AUTOMATION_KEY` on Render |
| `VULNEX_API_URL` | variable | `https://vulnex-1k5h.onrender.com` |
| `VULNEX_AI_API_KEY` | secret, optional | Only if you do not use GitHub Models |

### Who the PRs are credited to

GitHub credits a PR, its description and any comment to **the owner of the token**, whatever name is on the commits. A token made from your own account makes every PR look like you wrote it. So:

1. Sign in to GitHub as the automation account, and add `vulnexsecurityautomation@gmail.com` as a verified email there (this also links its commits to the account).
2. From the repository owner's account, invite that account as a **collaborator with Write access** on `akhila-dev5/azurelinux-test`, and accept the invitation as the automation account.
3. As the automation account, create the token (Settings > Developer settings > Personal access tokens). A fine-grained token cannot reach another person's personal repository, so if azurelinux-test is not offered in its repository list, use a **classic token** with the `repo` scope instead.
4. Save it as `AZL_TEST_TOKEN`, and set the variable `VULNEX_AUTOMATION_GITHUB_LOGIN` to that account's username.

At start-up the worker asks GitHub whose token it holds. If it is the repository owner's (or not the named login) it stops with a clear message before doing anything.

The workflow runs every 30 minutes and can be started by hand (with a **dry run** option that does everything except push and open the PR). To start it the moment you press Automate, add `VULNEX_DISPATCH_TOKEN` on Render: a fine-grained token for the vulnex repo with Actions set to read and write.

Local trial: `VULNEX_API_URL=... VULNEX_AUTOMATION_KEY=... AZL_TEST_TOKEN=... python -m vulnex.automation --dry-run` (needs `git`, `patch`, `tar`).

## Where the code is

| Part | File (`backend/vulnex/automation/`) |
|---|---|
| Spec edits | `specfile.py` |
| Git and patch steps | `patching.py`, `apply_patches.sh` |
| AI backport and client | `backport.py`, `ai.py` |
| Safety guards, PR client, titles | `pr.py` |
| One job from start to PR | `runner.py` |
| Worker (talks to the API) | `__main__.py` |
