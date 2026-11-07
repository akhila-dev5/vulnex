# 6. Scanning and verification

## Steps

```
1. collect     Read every .spec (and patch file list) from azurelinux-test with GitHub's tree API
2. parse       Name, version, release, Source, Patch: lines, CVE ids, .nopatch markers, %changelog
3. match       Ask OSV for "Azure Linux" advisories; compare versions with rpmvercmp
4. verify      Combine the range match with what the recipe says; set status, confidence, evidence
5. corroborate Cross-check CVE ids against Red Hat, Debian, Ubuntu, Alpine (OSV)
6. enrich      Add severity, references, upstream fix commit from NVD, MITRE, Red Hat, GHSA
7. save        Replace the SQLite snapshot, then sync to PostgreSQL if configured
```

Run it with `python -m vulnex.cli scan --branches 3.0`. Only stable branches `3.0` and `4.0` are accepted; the dashboard defaults to 3.0.

## Package identity

A package is identified by **branch + spec path**, not by name, because one name can have many specs (`golang.spec`, `golang-1.23.spec`, ...). Each spec is kept; the one named `<name>.spec` is marked primary.

## Version comparison

An advisory says a CVE affects a package from version A until it is fixed in version B (or `last_affected`). `rpmvercmp.py` compares versions the way RPM does:

- numbers beat letters, leading zeros are ignored
- `~` sorts before the base version (`1.0~rc1 < 1.0`)
- `^` sorts after it (`1.0^git1 > 1.0`)

If the package version lies inside the range, the CVE is a candidate.

## Statuses

| Status | When | Base confidence |
|--------|------|-----------------|
| `affected` | In the vulnerable range and the recipe does not fix it | 0.75 |
| `patched` | The recipe applies a patch naming the CVE, or its changelog names it | 0.90 |
| `false_positive` | The recipe has a `CVE-*.nopatch` marker | 0.92 |
| `unconfirmed` | The advisory mentions the package but gives no usable range | 0.40 |

Confidence rises when a patch file really exists in the repo or other distributions agree, and falls when a declared patch file is missing. Every finding stores its evidence text, so the UI can explain the verdict.

## Patched, fixed and "patch available"

- **Patched / fixed** (azurelinux-test): the spec contains the fix. The finding gets `fixed_in`, the version-release from the changelog entry that first names the CVE. If no entry names it, the scanned package's own version-release is used and marked as an estimate (`fixed_in_basis = spec-evr`).
- **Patch available** (upstream): an upstream patch exists for a CVE that is still open. It never means the spec has a `CVE-*.patch` file.

## The fixed-CVE list

After each scan, `fixed_cves.py` builds `data/fixed-cves.json` (CVE id, package, fixed version-release, basis) and publishes it to the `VulnerabilityData` repository. That repository regenerates its CVE inventory every few hours, and its own scanner reads this list to mark those CVEs `fixed` with the version-release.

```
vulnex.cli fixed-cves     build / publish the list
```

## Data sources

| Source | Used for |
|--------|----------|
| OSV.dev (`Azure Linux:3`) | Main detection: advisories with fixed / last-affected versions |
| OSV.dev (Red Hat, Debian, Ubuntu, Alpine) | Corroborating that a CVE applies |
| NVD | CVSS score, CWE, references (`NVD_API_KEY` raises rate limits) |
| MITRE CVE | CVE description and identity |
| Red Hat Security Data | Severity and fixed versions |
| GitHub Security Advisories | Corroboration, upstream fix discovery |
| GitHub tree and raw API | Spec and patch files |
| VulnerabilityData repo | Prepared NVD inventory per package version |

All are free. The scan needs no credentials; `GITHUB_TOKEN` only raises the GitHub rate limit.

## Triage views built from the data

`triage.py` adds three derived views to each finding without extra network calls:

- `links`: Ubuntu, Debian, Red Hat, MITRE, OSV and NVD pages for the CVE
- `patch_availability`: upstream patch verdict and links
- `deep`: files the fix touches in the source tarball, and backport patch files

## What is removed from the database

To save free-tier storage, the daily scan deletes findings that are **100% patched**: the spec applies the CVE's patch file (`patch_status = applied`) **and** its `%changelog` names the fix (`fixed_in_basis = changelog`).

A finding is deleted only if the fixed-CVE list on `VulnerabilityData` (main branch) already records it, so nothing is lost. If that list cannot be read, nothing is deleted. Findings that are patched but not fully confirmed stay, and are listed after the affected ones.

```
vulnex.cli prune-patched --branch 3.0 [--dry-run]
```

Comments, disputes and PR links people saved are not touched.

## Order of the CVE list

### Where severity comes from

Enrichment asks NVD, MITRE (the CVE Program record), Red Hat and GHSA. The first source with a numeric CVSS score wins, in that order. NVD's own score is preferred, but when NVD has not analysed a CVE yet ("NVD assessment not yet provided") the score from CISA-ADP or the CNA is used instead, from either NVD or the MITRE record. CVEs that still have no severity are enriched first, and `--enrich-limit` defaults to 5000, so a limit can no longer leave them as Unknown. A CVE can still show Unknown if no source has scored it; an administrator can then **Rescore** it.

Affected CVEs come first. A CVE sorts by its most urgent package, then by severity; all rows of one CVE stay together with affected packages first.

