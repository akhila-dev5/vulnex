import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, request } from "./client";

afterEach(() => vi.unstubAllGlobals());

const reply = (body: string, status: number, type = "text/html") =>
  vi.stubGlobal("fetch", async () => new Response(body, { status, headers: { "Content-Type": type } }));

describe("request errors", () => {
  it("uses the server's own message when it sends one", async () => {
    reply(JSON.stringify({ detail: "Database unavailable. Use the Session pooler." }), 503, "application/json");
    await expect(request("/findings")).rejects.toMatchObject({ message: "Database unavailable. Use the Session pooler.", status: 503 });
  });

  it("explains a gateway timeout that arrives as an HTML page", async () => {
    reply("<html>504 Gateway Time-out</html>", 504);
    const error: ApiError = await request("/findings").then(() => new ApiError("no error", 0), (e: ApiError) => e);
    expect(error.status).toBe(504);
    expect(error.message).toMatch(/took too long.*HTTP 504/);
  });

  it("names the status for any other empty failure", async () => {
    reply("", 500);
    await expect(request("/findings")).rejects.toMatchObject({ message: "Request failed (HTTP 500)" });
  });
});
