const RETRYABLE = new Set([408, 429, 500, 502, 503, 504]);

/**
 * fetch with retries for rate limits, server errors and dropped connections,
 * backing off exponentially (honouring Retry-After when the server sends it).
 */
export async function fetchWithRetry(url: string, init?: RequestInit, attempts = 4, baseDelayMs = 500): Promise<Response> {
  for (let i = 1; ; i++) {
    let res: Response | undefined;
    let error: unknown;
    try {
      res = await fetch(url, init);
      if (!RETRYABLE.has(res.status)) return res;
    } catch (e) {
      error = e;
    }
    if (i >= attempts) {
      if (res) return res;
      throw error;
    }
    const retryAfter = Number(res?.headers.get("retry-after"));
    const delay = retryAfter > 0 ? Math.min(retryAfter * 1000, 30_000) : baseDelayMs * 2 ** (i - 1);
    await new Promise((r) => setTimeout(r, delay));
  }
}
