import type { Finding } from "../api/types";

const BOUND_NOTE =
  "No changelog entry names this CVE, so this is the version-release of the scanned package (the fix shipped in it or earlier).";

/**
 * The azurelinux-test version-release in which a CVE was patched.
 * Blank while the CVE is unfixed; never the upstream project's version.
 */
export function AzlFixedVersion({ finding }: { finding: Finding }) {
  const version = finding.azl_fixed_version;
  if (!version) return <>—</>;
  if (finding.azl_fixed_basis === "spec-evr") {
    return (
      <span title={BOUND_NOTE}>
        {version} <span className="sr-only">({BOUND_NOTE})</span>
        <span aria-hidden="true">*</span>
      </span>
    );
  }
  return <>{version}</>;
}
