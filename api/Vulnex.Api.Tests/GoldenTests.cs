using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace Vulnex.Api.Tests;

/// <summary>
/// Every read endpoint must answer exactly what the golden files say. The files were recorded from
/// the original Python API on the data created by <c>scripts/api_snapshots.py seed</c>.
/// </summary>
[Trait("Suite", "Golden")]
public class GoldenTests : IClassFixture<ApiFactory>
{
    // Same list as VOLATILE in scripts/api_snapshots.py: values stamped with the clock at seed time.
    static readonly HashSet<string> Volatile = new()
    {
        "time", "expires_at", "_fetched_at",
        "created_at", "updated_at", "first_seen", "rescored_at", "started_at", "finished_at", "requested_at",
    };

    readonly ApiFactory _factory;
    public GoldenTests(ApiFactory factory) => _factory = factory;

    public static IEnumerable<object[]> Files() =>
        Directory.GetFiles(Path.Combine(AppContext.BaseDirectory, "golden"), "*.json").OrderBy(f => f)
            .Select(f => new object[] { Path.GetFileName(f) });

    [Theory]
    [MemberData(nameof(Files))]
    public async Task Endpoint_matches_its_golden_file(string file)
    {
        var golden = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "golden", file)))!;
        var path = golden["path"]!.GetValue<string>();

        var reply = await _factory.CreateClient().Get(path);

        var problems = new List<string>();
        if (reply.Code != golden["status"]!.GetValue<int>())
            problems.Add($"status: expected {golden["status"]}, got {reply.Code}");
        Diff(Strip(golden["body"]), Strip(reply.Body), "$", problems);
        Assert.True(problems.Count == 0, $"{path}\n  " + string.Join("\n  ", problems.Take(15)));
    }

    static JsonNode? Strip(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
                var copy = new JsonObject();
                foreach (var (key, value) in obj)
                    if (!Volatile.Contains(key)) copy[key] = Strip(value);
                return copy;
            case JsonArray arr:
                var list = new JsonArray();
                foreach (var item in arr) list.Add(Strip(item));
                return list;
            default:
                return node?.DeepClone();
        }
    }

    static void Diff(JsonNode? want, JsonNode? got, string path, List<string> problems)
    {
        if (want is null || got is null)
        {
            if (!(want is null && got is null)) problems.Add($"{path}: expected {want?.ToJsonString() ?? "null"}, got {got?.ToJsonString() ?? "null"}");
            return;
        }
        switch (want)
        {
            case JsonObject w when got is JsonObject g:
                foreach (var key in w.Select(p => p.Key).Union(g.Select(p => p.Key)).OrderBy(k => k))
                {
                    if (!w.ContainsKey(key)) problems.Add($"{path}.{key}: only in the .NET answer");
                    else if (!g.ContainsKey(key)) problems.Add($"{path}.{key}: missing from the .NET answer");
                    else Diff(w[key], g[key], $"{path}.{key}", problems);
                }
                break;
            case JsonArray w when got is JsonArray g:
                if (w.Count != g.Count) problems.Add($"{path}: expected {w.Count} items, got {g.Count}");
                for (var i = 0; i < Math.Min(w.Count, g.Count); i++) Diff(w[i], g[i], $"{path}[{i}]", problems);
                break;
            case JsonValue w when got is JsonValue g:
                if (w.GetValueKind() == JsonValueKind.Number && g.GetValueKind() == JsonValueKind.Number)
                {
                    if (Math.Abs(w.GetValue<double>() - g.GetValue<double>()) > 1e-9)
                        problems.Add($"{path}: expected {w.ToJsonString()}, got {g.ToJsonString()}");
                }
                else if (w.ToJsonString() != g.ToJsonString())
                    problems.Add($"{path}: expected {w.ToJsonString()}, got {g.ToJsonString()}");
                break;
            default:
                problems.Add($"{path}: different JSON types ({want.GetValueKind()} vs {got.GetValueKind()})");
                break;
        }
    }
}
