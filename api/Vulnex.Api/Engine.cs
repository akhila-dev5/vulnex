using System.Diagnostics;
using System.Text.Json;

namespace Vulnex.Api;

/// <summary>The engine reported a feed problem (the API answers 502).</summary>
public sealed class FeedException : Exception
{
    public FeedException(string message) : base(message) { }
}

/// <summary>
/// Runs the Python engine (<c>python -m vulnex.engine_bridge</c>) for the work that stays in
/// Python: CVE enrichment, the fixed-CVE ledger, the VulnerabilityData feed and scans.
/// </summary>
public sealed class Engine
{
    readonly string _python;
    readonly string _workDir;

    public Engine()
    {
        _python = Environment.GetEnvironmentVariable("VULNEX_PYTHON") ?? "python3";
        // The Docker image sets VULNEX_BACKEND_DIR; locally it is ../backend next to api/.
        _workDir = Environment.GetEnvironmentVariable("VULNEX_BACKEND_DIR") ?? FindBackendDir();
    }

    static string FindBackendDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "backend");
            if (Directory.Exists(Path.Combine(candidate, "vulnex"))) return candidate;
            dir = dir.Parent;
        }
        return Path.Combine(Directory.GetCurrentDirectory(), "backend");
    }

    ProcessStartInfo Start(IEnumerable<string> args)
    {
        var psi = new ProcessStartInfo(_python)
        {
            WorkingDirectory = _workDir,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add("-m");
        psi.ArgumentList.Add("vulnex.engine_bridge");
        foreach (var a in args) psi.ArgumentList.Add(a);
        return psi;
    }

    /// <summary>Run one command to completion and return its single JSON document.</summary>
    public async Task<object?> RunJsonAsync(params string[] args)
    {
        using var proc = Process.Start(Start(args)) ?? throw new InvalidOperationException("Could not start the Python engine.");
        var stdout = await proc.StandardOutput.ReadToEndAsync();
        var stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();

        var lastLine = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? "null";
        object? parsed;
        try { parsed = Json.Loads(lastLine, null); }
        catch (JsonException) { parsed = null; }

        if (proc.ExitCode == 0) return parsed;
        var message = (parsed as Row)?.Str("error");
        if (string.IsNullOrEmpty(message)) message = stderr.Trim();
        if (string.IsNullOrEmpty(message)) message = "The Python engine failed.";
        if (proc.ExitCode == 3) throw new FeedException(message!);
        throw new InvalidOperationException(message);
    }

    /// <summary>Run <c>scan</c>, calling <paramref name="onLine"/> for each JSON line it prints.</summary>
    public async Task<int> RunScanAsync(string optionsJson, Action<Row> onLine)
    {
        using var proc = Process.Start(Start(new[] { "scan", "--options", optionsJson }))
                         ?? throw new InvalidOperationException("Could not start the Python engine.");
        var stderrTask = proc.StandardError.ReadToEndAsync();
        string? line;
        while ((line = await proc.StandardOutput.ReadLineAsync()) is not null)
        {
            if (line.Length == 0) continue;
            if (Json.Loads(line, null) is Row row) onLine(row);
        }
        await proc.WaitForExitAsync();
        var stderr = await stderrTask;
        if (proc.ExitCode != 0 && stderr.Length > 0)
            onLine(new Row { ["type"] = "error", ["error"] = stderr.Trim() });
        return proc.ExitCode;
    }
}

/// <summary>Runs at most one scan at a time in the background (same state shape as before).</summary>
public sealed class ScanManager
{
    readonly object _lock = new();
    readonly Engine _engine;
    readonly ResponseCache _cache;
    Row _state = Fresh();

    public ScanManager(Engine engine, ResponseCache cache)
    {
        _engine = engine;
        _cache = cache;
    }

    static string Now() => Sql.UtcNow();

    static Row Fresh() => new()
    {
        ["running"] = false, ["stage"] = "idle", ["started_at"] = null, ["finished_at"] = null,
        ["log"] = new List<Row>(), ["result"] = null, ["error"] = null,
    };

    void Log(string message)
    {
        lock (_lock)
        {
            var log = (List<Row>)_state["log"]!;
            log = log.Append(new Row { ["at"] = Now(), ["message"] = message }).TakeLast(60).ToList();
            _state["stage"] = message;
            _state["log"] = log;
            _state["started_at"] ??= Now();
        }
    }

    public bool Start(object options)
    {
        lock (_lock)
        {
            if ((bool)_state["running"]!) return false;
            _state = new Row
            {
                ["running"] = true, ["stage"] = "starting", ["started_at"] = Now(), ["finished_at"] = null,
                ["log"] = new List<Row>(), ["result"] = null, ["error"] = null,
            };
        }
        var json = Json.Dumps(options);
        _ = Task.Run(() => RunAsync(json));
        return true;
    }

    async Task RunAsync(string optionsJson)
    {
        try
        {
            var exit = await _engine.RunScanAsync(optionsJson, line =>
            {
                switch (line.Str("type"))
                {
                    case "progress":
                        Log(line.Str("message"));
                        break;
                    case "result":
                        lock (_lock) { _state["result"] = line.Get("result"); _state["stage"] = "complete"; }
                        break;
                    case "error":
                        lock (_lock) { _state["error"] = line.Str("error"); _state["stage"] = "failed"; }
                        break;
                }
            });
            lock (_lock)
            {
                if (exit != 0 && _state["error"] is null)
                {
                    _state["error"] = $"The scan engine exited with code {exit}.";
                    _state["stage"] = "failed";
                }
            }
        }
        catch (Exception ex)
        {
            lock (_lock) { _state["error"] = ex.Message; _state["stage"] = "failed"; }
        }
        finally
        {
            _cache.Clear();
            lock (_lock)
            {
                _state["running"] = false;
                _state["finished_at"] = Now();
            }
        }
    }

    public Row Status()
    {
        lock (_lock) return new Row(_state);
    }
}
