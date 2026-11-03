# Step 1: Source inspection

**Status:** complete. Documentation only; no application code changed.
**Inspected on:** 2026-10-29.
**Method:** shallow `git clone` of each permitted repository, then short throwaway Python
scripts over the files. Every number below was computed from the pinned commits; nothing is
quoted from a README without being checked against the data. The scripts were not kept;
Step 3 replaces them with tests that run against fixtures.

## 1. Sources and pinned revisions

| Source | Ref | Commit | Commit date |
| --- | --- | --- | --- |
| `akhila-dev5/VulnerabilityData` | default branch | `560b7599e260132c94c8ae8c043fb6beb8d958f4` | 2026-10-28 12:59:24 UTC |
| `akhila-dev5/azurelinux-test` | `3.0` (repo default) | `a526a629b8ff3db2ec8a9633803506bd61118bca` | 2026-09-23 |
| `akhila-dev5/azurelinux-test` | `main` | `ad24d4621f55a6764d28e7717eed80d00cd2ce1f` | 2025-11-14 |
| `akhila-dev5/vulnex` (this repo) | `main` | `9a6081d4c522d1db96f5a8e0c21313025621c09d` | n/a |

`azurelinux-test` has 956 branches. Two of them matter here (see section 4).

## 2. VulnerabilityData

### 2.1 Layout

| Path | What it is |
| --- | --- |
| `data/azurelinux-test.json` | Per-package CVE inventory, 3.5 MB. **The best ingestion source.** |
| `oval/azurelinux-test.xml` | OVAL 5.11.1 definitions, 2.9 MB. Contains 2,162 definitions, CPE matches only (no keyword matches). It carries less than the JSON, so it is not needed. |
| `scripts/scan.py` | The generator: manifest + NVD feeds, producing the two files above. |
| `.github/workflows/update.yml` | Regenerates the data every 6 hours (`17 */6 * * *`) and commits it. |

How the data is made (from `README.md` and `scripts/scan.py`): `scan.py` reads
`cgmanifest.json` from `azurelinux-test`, matches every package name and version against the
NVD CVE JSON 2.0 feeds, and writes the two documents. **Vulnex must never run `scan.py`.** It
treats the output files as data only. That keeps Vulnex from calling NVD directly and from
executing repository content.

There are two matching rules in `scan.py`:

- **`cpe`**: an NVD configuration entry (CPE) names a product matching the package name
  (exact name, separator-prefix, vendor+product concatenation, or a small alias table such as
  `golang`→`go`). Version ranges are then evaluated against the manifest version with an
  rpmvercmp-compatible comparator; only in-range matches are kept.
- **`keyword`**: the CVE *description* mentions the package name as a whole word. Used only
  for packages that have no CPE matches at all, and **never filtered by version**.

### 2.2 JSON schema (`schema_version: 1`)

```
{
  "schema_version": 1,
  "generated_at": "2026-10-28T12:59:24Z",
  "source": { "manifest": <url>, "distro": "azurelinux-test", "nvd_feeds": <url>, "scanner": <path> },
  "stats":  { packages, packages_with_findings, findings, by_match, excluded_by_version,
              by_severity, scan_seconds },
  "packages": [
    { "name": str, "versions": [str], "tarball": url,
      "cves": [
        { "id": "CVE-YYYY-NNNN", "match": "cpe" | "keyword",
          "severity": "CRITICAL|HIGH|MEDIUM|LOW|NONE|UNASSIGNED",
          "cvss_score": number|null, "cvss_vector": str|null,
          "published": str, "last_modified": str,
          "description": str|null,
          "ranges": [ {versionStartIncluding?, versionStartExcluding?,
                       versionEndIncluding?, versionEndExcluding?, version?} ],
          "affected_versions": [str] } ] } ]
}
```

### 2.3 What the data actually contains

All figures are computed from the rows, not from the file's own `stats` block.

| Measure | Value |
| --- | --- |
| Packages listed in `packages` (only those with findings) | 473 |
| Package-CVE rows ("occurrences") | 7,177 |
| Distinct CVE ids | 7,042 |
| CVEs that appear under more than one package | 110 (maximum 8 packages) |
| Duplicate (package, CVE) pairs | 0 |
| Malformed CVE ids | 0 |
| `match = cpe` rows | 2,200 (30.7%) |
| `match = keyword` rows | **4,977 (69.3%)** |
| Rows with `description = null` | 4,977, exactly the keyword rows |
| Rows with empty `ranges` | 4,977, exactly the keyword rows |
| Rows with `severity = UNASSIGNED` (and null CVSS) | 334, all keyword rows |
| Longest description | 400 characters (truncated by `scan.py`) |

## 3. Observations that shape the design

1. **Most rows are unverified.** Over two thirds of rows are keyword mentions. They ship with
   no version range and no description, so nothing in the feed lets a reader check them. These
   must be stored and labelled as unverified, never counted as confirmed.
2. **Even `cpe` rows rely on a name-matching heuristic.** Package names are mapped to CPE
   product names by exact, prefix and alias rules (`NameIndex` in `scan.py`). The version check
   is real, but the *which product is this* step can collide. "Version in range" is therefore
   "supported by NVD data", not proof.
3. **294 of the 2,200 `cpe` rows have no version evidence.** Their only range entries are
   empty (`{}`, 344 entries in total): a CPE with a wildcard version and no bounds, meaning NVD
   says "all versions". It matches the shipped version trivially. The other 1,906 `cpe` rows
   split into 1,791 with at least one bounded range (`versionStart*`/`versionEnd*`) and 115 that
   pin a single version. No row mixes empty and non-empty ranges. The unbounded rows need
   their own label.
4. **There is no "fixed version" field.** `versionEndExcluding` is the *upstream* fix
   version in NVD, not a distro-fixed version. The dashboard must not present it as
   "fixed in Azure Linux".
5. **Versions are upstream versions, not RPM EVRs.** The manifest has `name`, `version`,
   `downloadUrl` only: no release, no epoch, no architecture.
6. **The file's `stats` block disagrees with its rows.** `stats.findings` = 7,177 (matches the
   rows), but `by_match` and `by_severity` each sum to 7,222; for example `cpe` is reported as
   2,245 but there are 2,200 rows. Vulnex must recompute every statistic from stored rows and
   never display the feed's `stats`.
7. **Metadata is consistent across packages.** For the 110 CVEs listed under several
   packages, severity, CVSS score/vector, published and modified values never conflict. The
   only inconsistency: for 26 of them, `description` is null in some rows and present in
   others. Normalization rule: take the non-null description when merging per CVE.
8. **Timestamps have no timezone** (e.g. `2026-09-03T16:17:25.360`). They are passed through
   from NVD unchanged. NVD's convention is UTC, but this is **an assumption to record in the
   code and docs**, because the sources do not state it.
9. **The feed does not record which `azurelinux-test` commit it used**, only a URL that names
   a branch (`.../main/cgmanifest.json`). See section 4.

## 4. azurelinux-test

### 4.1 Layout (branch `3.0`, 13,342 files)

| Path | Files | Role |
| --- | --- | --- |
| `SPECS/` | 7,114 | RPM spec trees, one directory per spec |
| `SPECS-EXTENDED/` | 5,138 | Extended spec trees |
| `SPECS-SIGNED/` | 25 | Signed-package specs |
| `toolkit/`, `.pipelines/`, `.github/` | 820 / 187 / 35 | Build tooling and CI (not data sources) |
| `cgmanifest.json` | 1 | Component manifest, the input to the vulnerability scan |

### 4.2 `cgmanifest.json` schema

```
{ "Version": 1,
  "Registrations": [ { "component": { "type": "other",
                                      "other": { "name": str, "version": str, "downloadUrl": url } } } ] }
```

On `3.0`: 3,176 registrations, 3,164 distinct names (7 names appear with several versions,
e.g. `golang`, `rust`, `rdma-core`). On `main`: 3,091 registrations, 3,086 distinct names.

### 4.3 Key finding: the vulnerability feed was generated from `main`, not the default branch

`VulnerabilityData/scripts/scan.py` defaults to
`https://raw.githubusercontent.com/akhila-dev5/azurelinux-test/main/cgmanifest.json`.
Compared against the real manifests:

- All 473 packages in the feed, and every version listed for them, match `main`'s manifest
  **exactly** (and `stats.packages` = 3,091 = main's registration count).
- Against branch `3.0`, 20 of those packages are absent and **294 of the other 453 have a
  different version** (e.g. `Cython` 0.29.33 in the feed vs 3.0.5 on `3.0`).
- `main` last changed on 2025-11-14. `3.0` is the repository default and changed on
  2026-09-23.
- `VulnerabilityData/README.md` says "3,176 packages today"; that is the `3.0` count, not what
  the feed scanned (3,091).

Consequence: the dashboard would show CVEs for package versions of the older `main` snapshot
while the repository's default branch ships different versions. Vulnex must show which
manifest revision the data describes and must not imply it describes `3.0`.

### 4.4 Spec tree as corroborating evidence (measured on `main`)

The spec directories can show whether the distro has already patched a CVE. Matching only on
**file names** (no spec parsing yet), using the tree listing of `main`:

| Measure | Value |
| --- | --- |
| Manifest names equal to a spec directory name | 2,954 of 3,086 |
| Feed packages that map to a same-named spec directory | 462 of 473 |
| Feed rows whose CVE id appears in a patch/marker file name in that package's directory | 367 of 7,177 (5.1%): 362 `cpe`, 5 `keyword` |
| Of those, `*.nopatch` markers (distro says "not applicable") | 30 |

Worked example, verified in the spec:
the feed flags `LibRaw` 0.19.5 for `CVE-2020-15503` (`cpe`, `versionEndIncluding: 0.19.5`),
but `SPECS-EXTENDED/LibRaw/LibRaw.spec` on `main` declares `Patch1: CVE-2020-15503.patch` and
applies it with `%patch1`. A version-only scan calls this affected; the spec shows the distro
carries a fix. This is why the plan treats spec evidence as a separate signal rather than
trusting version ranges alone.

Caveats: file-name matching can miss patches that are not named after the CVE, and I did not
parse `Patch:` directives. A name→spec-directory mapping exists for most but not all packages.

## 5. What the permitted sources cannot tell us

- Whether a CVE affects an *Azure Linux build* of a package: the feed knows upstream versions
  only.
- A distro-fixed version.
- Any architecture or RPM release.
- Why a keyword row matched, and whether it is a true positive.
- Which `azurelinux-test` commit produced a given feed: this has to be inferred and recorded
  by Vulnex (see the implementation plan).

The ingestion and UI must report these as unknown rather than fill the gaps.

## 6. Existing Vulnex repository vs the new requirements

The current repository (about 8.5k lines of Python and JavaScript including tests) works, but
it was built to a different brief. These items conflict with the new requirements:

| Existing behavior | Where | Conflict |
| --- | --- | --- |
| Pulls data from OSV.dev, NVD, MITRE, Red Hat, GitHub Advisories | `backend/vulnex/sources/*`, `enrichment.py` | Only the two permitted repos may supply data |
| Reads the spec tree from Microsoft's `azurelinux` repo over the GitHub API | `azurelinux.py` | Only `akhila-dev5/azurelinux-test` is permitted |
| SQLite, with a 21 MB populated `data/vulnex.db` committed and re-committed daily | `db.py`, `data/`, `scan.yml` | Requires PostgreSQL; a populated database must not be in source control |
| "Assign to Patch Automation" queue and an "AI verdict" panel | `api.py`, `triage.py` | AI automation and remediation are out of scope |
| Admin is a GitHub account allow-list; the automation key falls back to the literal `"vulnex-sec"` | `config.py`, `auth.py` | Admin must be the verified email identity; no hard-coded fallback secrets |
| Read-only static export on GitHub Pages | `export.py`, workflow | Replaced by API + database |
| Triage workflow (comments, disputes, patch verdicts, GitHub PR links) | `triage.py`, `api.py` | Not in the new requirements; needs an owner decision |

Worth keeping: `rpmvercmp.py` and its tests, and `spec_parser.py`'s handling of `Patch:` and
`*.nopatch`, as a starting point for the spec-evidence signal.

## 7. Open uncertainties

1. Which `azurelinux-test` branch should Vulnex represent: `main` (what the feed describes) or
   `3.0` (the default branch)? See decision D1 in the plan.
2. Whether NVD timestamps are UTC (assumed; see section 3, item 8).
3. Whether `VulnerabilityData` will record the manifest commit in future. Until it does,
   Vulnex derives it itself.
4. GitHub API rate limits when resolving refs without a token (expected to be sufficient for
   a handful of calls per run; to be confirmed in Step 3).
