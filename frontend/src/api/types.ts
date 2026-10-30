// Shapes returned by the Vulnex FastAPI backend (backend/vulnex/api.py).

export type RoleInfo = {
  role: "viewer" | "admin" | "automation";
  identity?: { identity?: string; email?: string };
  methods?: { google?: boolean; google_email?: string };
  write_enabled?: boolean;
  can_comment?: boolean;
  can_dispute?: boolean;
  can_triage?: boolean;
  can_scan?: boolean;
  can_set_patch_verdict?: boolean;
  can_set_pr?: boolean;
};

/** Per-finding workflow state stored by the backend (finding_triage table). */
export type TriageRecord = {
  triage_status?: string;
  resolution_status?: string;
  final_verdict?: string;
  patch_link?: string;
  available_since?: string;
  github_pr_number?: string;
  github_pr_url?: string;
  github_pr_set_by?: string;
  github_pr_set_at?: string;
  owner?: string;
  updated_at?: string;
};

export type PatchAvailability = {
  applicable?: boolean;
  available?: boolean;
  /** Rule-based label computed by the backend from upstream references (not a model output). */
  ai_verdict?: string;
  final_verdict?: string;
  possible_links?: string[];
  analysis?: string[];
  patch_link?: string;
  available_since?: string;
};

export type Finding = {
  cve_id: string;
  package_name: string;
  package_version?: string;
  branch: string;
  spec_path: string;
  /** Scanner verdict: affected, patched, false_positive or unconfirmed. */
  status?: string;
  severity?: string;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  description?: string;
  fixed_version?: string;
  advisory_id?: string;
  source?: string;
  triage?: TriageRecord | null;
  patch_availability?: PatchAvailability;
  assignment?: { assignee_email?: string; status?: string; notes?: string } | null;
};

export type PageResult<T> = { items: T[]; total: number; page?: number; limit?: number };

export type PackageRow = { name: string; version?: string; branch?: string; spec_path?: string };

export type FindingComment = {
  id?: number;
  kind?: string;
  author?: string;
  body?: string;
  created_at?: string;
};

export type DeepView = {
  cve_id?: string;
  package_name?: string;
  package_version?: string;
  branch?: string;
  spec_path?: string;
  spec_url?: string;
  tarball?: { name?: string; url?: string; available?: boolean | null } | null;
  affected_files?: Array<string | { path?: string; file?: string; url?: string; name?: string }>;
  backport_patches?: Array<{ filename?: string; url?: string; present?: boolean | null }>;
  notes?: string[];
};

export type CveDetail = {
  cve_id?: string;
  findings?: Finding[];
  enrichment?: {
    description?: string;
    published?: string;
    modified?: string;
    cvss_score?: number;
    severity?: string;
    references?: Array<{ url?: string; name?: string }>;
  } | null;
  links?: Array<{ label: string; url: string }>;
};

export type Stats = {
  total_packages?: number;
  total_findings?: number;
  distinct_cves?: number;
  severity?: Record<string, number>;
  last_scan?: { finished_at?: string; started_at?: string; branches?: string; status?: string };
  repository?: { owner?: string; repo?: string; branches?: string[] };
};
