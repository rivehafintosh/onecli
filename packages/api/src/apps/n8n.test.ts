import { afterEach, describe, expect, it, vi } from "vitest";
import { n8nAppInternals } from "./n8n";

describe("n8n app", () => {
  afterEach(() => vi.restoreAllMocks());

  it("normalizes a self-hosted base URL with a path prefix", () => {
    const base = n8nAppInternals.normalizeBaseUrl(
      "n8n.example.com/automation/",
    );
    expect(base.toString()).toBe("https://n8n.example.com/automation");
    expect(n8nAppInternals.apiUrl(base, "/api/v1/workflows?limit=1")).toBe(
      "https://n8n.example.com/automation/api/v1/workflows?limit=1",
    );
  });

  it("rejects non-HTTP base URLs", () => {
    expect(() =>
      n8nAppInternals.normalizeBaseUrl("ftp://n8n.example.com"),
    ).toThrow("n8n Base URL must use HTTP or HTTPS");
  });

  it("validates and stores a host-gated API key", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("{}", { status: 200 }));

    const result = await n8nAppInternals.exchangeCredentials({
      baseUrl: "https://n8n.example.com/",
      apiKey: "secret-key",
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "https://n8n.example.com/api/v1/workflows?limit=1",
      { headers: { "X-N8N-API-KEY": "secret-key" } },
    );
    expect(result.credentials).toMatchObject({
      access_token: "secret-key",
      apiKey: "secret-key",
      instance_host: "n8n.example.com",
      instance_url: "https://n8n.example.com",
    });
  });
});
