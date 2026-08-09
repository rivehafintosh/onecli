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
      apiKey: "secret-key",
      instance_host: "n8n.example.com",
      instance_url: "https://n8n.example.com",
    });
  });

  it("bundles editor and MCP credentials into the same connection", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("{}", { status: 200 }));

    const result = await n8nAppInternals.exchangeCredentials({
      baseUrl: "https://n8n.example.com/automation",
      editorCookie: "n8n-auth=session; n8n-browserId=browser",
      mcpToken: "mcp-token",
    });

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://n8n.example.com/automation/rest/workflows?limit=1",
      {
        headers: {
          Cookie: "n8n-auth=session; n8n-browserId=browser",
        },
      },
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://n8n.example.com/automation/mcp-server/http",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          Authorization: "Bearer mcp-token",
        }),
      }),
    );
    expect(result.credentials).toMatchObject({
      editorCookie: "n8n-auth=session; n8n-browserId=browser",
      mcpToken: "mcp-token",
      instance_host: "n8n.example.com",
    });
  });

  it("requires at least one supported credential", async () => {
    await expect(
      n8nAppInternals.exchangeCredentials({
        baseUrl: "https://n8n.example.com",
      }),
    ).rejects.toThrow("Provide at least one n8n API key");
  });
});
