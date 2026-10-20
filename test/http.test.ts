import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchWithRetry } from "../src/http.js";

afterEach(() => vi.unstubAllGlobals());

function stubResponses(...steps: (number | Error)[]) {
  const calls: string[] = [];
  vi.stubGlobal("fetch", async (url: string) => {
    calls.push(url);
    const step = steps[Math.min(calls.length - 1, steps.length - 1)];
    if (step instanceof Error) throw step;
    return new Response("body", { status: step });
  });
  return calls;
}

describe("fetchWithRetry", () => {
  it("retries rate limits, server errors and network failures", async () => {
    const calls = stubResponses(429, new Error("ECONNRESET"), 503, 200);
    const res = await fetchWithRetry("https://x", undefined, 4, 1);
    expect(res.status).toBe(200);
    expect(calls).toHaveLength(4);
  });

  it("does not retry client errors", async () => {
    const calls = stubResponses(404, 200);
    expect((await fetchWithRetry("https://x", undefined, 4, 1)).status).toBe(404);
    expect(calls).toHaveLength(1);
  });

  it("gives up after the last attempt with the last response or error", async () => {
    stubResponses(503);
    expect((await fetchWithRetry("https://x", undefined, 3, 1)).status).toBe(503);
    stubResponses(new Error("offline"));
    await expect(fetchWithRetry("https://x", undefined, 2, 1)).rejects.toThrow("offline");
  });
});
