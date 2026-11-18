namespace Vulnex.Api;

// Request bodies. Property names map to snake_case JSON (cve_id, spec_path, ...), exactly
// the field names the React app and the automation worker already send.

public sealed class ScanRequest
{
    public List<string>? Branches { get; set; }
    public List<string>? Packages { get; set; }
    public int Limit { get; set; }
    public bool Enrich { get; set; } = true;
    public bool VerifyBlobs { get; set; } = true;
}

public sealed class AssignmentRequest
{
    public required string CveId { get; set; }
    public required string PackageName { get; set; }
    public string? SpecPath { get; set; }
    public string Notes { get; set; } = "";
    public string? TargetRepo { get; set; }
    public string AssigneeEmail { get; set; } = "";
}

public sealed class CommentRequest
{
    public required string Body { get; set; }
    public string? CveId { get; set; }
    public string Branch { get; set; } = "";
    public string SpecPath { get; set; } = "";
    public string? Author { get; set; }
}

public class FindingRef
{
    public required string CveId { get; set; }
    public string Branch { get; set; } = "";
    public string SpecPath { get; set; } = "";
}

public sealed class DisputeRequest : FindingRef
{
    public required string Reason { get; set; }
    public string FirstUnaffectedVersion { get; set; } = "";
    public bool NeverApplicable { get; set; }
}

public sealed class GithubPrRequest : FindingRef
{
    public required string Number { get; set; }
    public string Url { get; set; } = "";
}

public sealed class AutomationRequest
{
    public required string PackageName { get; set; }
    public string Branch { get; set; } = "";
    public string SpecPath { get; set; } = "";
    public List<string> CveIds { get; set; } = new();
    public required string Mode { get; set; }
    public string PrNumber { get; set; } = "";
}

public sealed class RescoreRequest
{
    public required string Severity { get; set; }
    public double? CvssScore { get; set; }
    public string Reason { get; set; } = "";
}

public sealed class PatchVerdictRequest : FindingRef
{
    public string FinalVerdict { get; set; } = "";
    public string PatchLink { get; set; } = "";
    public string AvailableSince { get; set; } = "";
}

public sealed class DisputeDecision
{
    public string Note { get; set; } = "";
}

public sealed class JobResult
{
    public required string Status { get; set; }
    public string Message { get; set; } = "";
    public string PrUrl { get; set; } = "";
    public string PrNumber { get; set; } = "";
    public string BranchName { get; set; } = "";
    public List<string> Fixed { get; set; } = new();
}
