using System.Text.Json;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.Extensions.FileProviders;
using Vulnex.Api;

var builder = WebApplication.CreateBuilder(args);

// Render (and most hosts) hand the app a PORT; fall back to Kestrel's default otherwise.
var port = Environment.GetEnvironmentVariable("PORT");
if (!string.IsNullOrEmpty(port)) builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

// Database: the same DATABASE_URL secret the Python backend used.
IDbFactory dbFactory = string.IsNullOrEmpty(Cfg.DatabaseUrl)
    ? new MissingDatabase()
    : new PgFactory(Cfg.DatabaseUrl);

builder.Services.AddSingleton(dbFactory);
builder.Services.AddSingleton(new HttpClient { Timeout = TimeSpan.FromSeconds(Math.Max(Cfg.HttpTimeoutSeconds, 5)) });
builder.Services.AddSingleton<SessionStore>();
builder.Services.AddSingleton<AuthService>();
builder.Services.AddSingleton<ResponseCache>();
builder.Services.AddSingleton<Engine>();
builder.Services.AddSingleton<ScanManager>();
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownIPNetworks.Clear();
    o.KnownProxies.Clear();
});
builder.Services.AddResponseCompression(o =>
{
    o.EnableForHttps = true;
    o.Providers.Add<GzipCompressionProvider>();
});
builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
{
    var origins = Cfg.AllowedOrigins;
    if (origins.Count > 0) p.WithOrigins(origins.ToArray()).AllowAnyMethod().AllowAnyHeader();
}));
builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.PropertyNamingPolicy = Json.Options.PropertyNamingPolicy;
    o.SerializerOptions.PropertyNameCaseInsensitive = true;
});

var app = builder.Build();

app.UseForwardedHeaders();
app.UseResponseCompression();
if (Cfg.AllowedOrigins.Count > 0) app.UseCors();

// Errors become {"detail": "..."} like FastAPI's HTTPException.
app.Use(async (ctx, next) =>
{
    try
    {
        await next();
    }
    catch (HttpError e)
    {
        await WriteDetail(ctx, e.Status, e.Message);
    }
    catch (DatabaseUnavailable e)
    {
        await WriteDetail(ctx, 503, $"Database unavailable. {e.Message}");
    }
    catch (Exception e) when (!ctx.Response.HasStarted)
    {
        app.Logger.LogError(e, "Unhandled error on {Path}", ctx.Request.Path);
        await WriteDetail(ctx, 500, "Internal Server Error");
    }
});

static Task WriteDetail(HttpContext ctx, int status, string detail)
{
    ctx.Response.Clear();
    ctx.Response.StatusCode = status;
    ctx.Response.ContentType = "application/json";
    return ctx.Response.WriteAsync(JsonSerializer.Serialize(new Dictionary<string, string> { ["detail"] = detail }));
}

// Any write drops the response cache.
var cache = app.Services.GetRequiredService<ResponseCache>();
app.Use(async (ctx, next) =>
{
    await next();
    if (!HttpMethods.IsGet(ctx.Request.Method) && !HttpMethods.IsHead(ctx.Request.Method) && !HttpMethods.IsOptions(ctx.Request.Method))
        cache.Clear();
});

Endpoints.Map(app);

// Unknown /api paths are JSON 404s, not the web page.
app.Map("/api/{**rest}", (HttpContext ctx) => WriteDetail(ctx, 404, "Not Found"));

// The built React app (Vite output), served from the same origin as the API.
static string? FindFrontend()
{
    var configured = Cfg.FrontendDir;
    if (configured.Length > 0) return Directory.Exists(configured) ? configured : null;
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null)
    {
        var candidate = Path.Combine(dir.FullName, "frontend", "dist");
        if (File.Exists(Path.Combine(candidate, "index.html"))) return candidate;
        dir = dir.Parent;
    }
    return null;
}

var frontend = FindFrontend();
if (frontend is not null)
{
    var files = new PhysicalFileProvider(frontend);
    app.UseDefaultFiles(new DefaultFilesOptions { FileProvider = files });
    app.UseStaticFiles(new StaticFileOptions { FileProvider = files });
}

app.Run();

/// <summary>Visible to the integration tests (WebApplicationFactory&lt;Program&gt;).</summary>
public partial class Program { }

/// <summary>Used when DATABASE_URL is not set: every request reports the database as unavailable.</summary>
sealed class MissingDatabase : IDbFactory
{
    public DbConnection Open() => throw new DatabaseUnavailable("DATABASE_URL is not set.");
}

/// <summary>Lets the integration tests start the app in memory.</summary>
public partial class Program { }
