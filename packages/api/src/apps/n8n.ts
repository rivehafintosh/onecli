import type { AppDefinition, OAuthExchangeResult } from "./types";

const normalizeBaseUrl = (value: string): URL => {
  const raw = value.trim();
  if (/^[a-z][a-z\d+.-]*:\/\//i.test(raw) && !/^https?:\/\//i.test(raw)) {
    throw new Error("n8n Base URL must use HTTP or HTTPS");
  }
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  const url = new URL(withScheme);
  if (!url.hostname) throw new Error("n8n Base URL must include a hostname");
  url.pathname = url.pathname.replace(/\/+$/, "");
  url.search = "";
  url.hash = "";
  return url;
};

const apiUrl = (baseUrl: URL, path: string): string => {
  const [pathname, query = ""] = path.split("?", 2);
  const url = new URL(baseUrl.toString());
  url.pathname = `${url.pathname.replace(/\/+$/, "")}${pathname}`;
  url.search = query;
  return url.toString();
};

const exchangeCredentials = async (
  fields: Record<string, string>,
): Promise<OAuthExchangeResult> => {
  const baseUrl = normalizeBaseUrl(fields.baseUrl!);
  const apiKey = fields.apiKey?.trim();
  const editorCookie = fields.editorCookie?.trim();
  const mcpToken = fields.mcpToken?.trim();
  if (!apiKey && !editorCookie && !mcpToken) {
    throw new Error(
      "Provide at least one n8n API key, editor cookie, or MCP access token",
    );
  }

  const checks: Promise<void>[] = [];
  if (apiKey) {
    checks.push(
      validateCredential(
        apiUrl(baseUrl, "/api/v1/workflows?limit=1"),
        { "X-N8N-API-KEY": apiKey },
        "public API key",
      ),
    );
  }
  if (editorCookie) {
    checks.push(
      validateCredential(
        apiUrl(baseUrl, "/rest/workflows?limit=1"),
        { Cookie: editorCookie },
        "editor session cookie",
      ),
    );
  }
  if (mcpToken) {
    checks.push(validateMcpCredential(baseUrl, mcpToken));
  }
  await Promise.all(checks);

  const instanceUrl = baseUrl.toString().replace(/\/$/, "");
  return {
    credentials: {
      ...(apiKey ? { apiKey } : {}),
      ...(editorCookie ? { editorCookie } : {}),
      ...(mcpToken ? { mcpToken } : {}),
      instance_host: baseUrl.host,
      instance_url: instanceUrl,
    },
    scopes: [],
    metadata: {
      name: baseUrl.host,
      username: baseUrl.host,
      instanceUrl,
      instanceHost: baseUrl.host,
    },
  };
};

const validateCredential = async (
  url: string,
  headers: Record<string, string>,
  label: string,
): Promise<void> => {
  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error(
      `Could not authenticate the n8n ${label} (${response.status} ${response.statusText})`,
    );
  }
};

const validateMcpCredential = async (
  baseUrl: URL,
  token: string,
): Promise<void> => {
  const response = await fetch(apiUrl(baseUrl, "/mcp-server/http"), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "onecli-connect",
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "onecli", version: "1" },
      },
    }),
  });
  if (!response.ok) {
    throw new Error(
      `Could not authenticate the n8n MCP access token (${response.status} ${response.statusText})`,
    );
  }
};

export const n8n: AppDefinition = {
  id: "n8n",
  name: "n8n",
  icon: "/icons/n8n.svg",
  description:
    "Manage workflows, executions, credentials, and projects in n8n.",
  connectionMethod: {
    type: "credentials_import",
    fields: [
      {
        name: "baseUrl",
        label: "Base URL",
        description:
          "The public URL of your n8n instance, including any configured path prefix.",
        placeholder: "https://n8n.example.com",
        secret: false,
      },
      {
        name: "apiKey",
        label: "API Key",
        description: "Create an API key under n8n Settings > API.",
        placeholder: "eyJhbGciOi...",
        secret: true,
        optional: true,
      },
      {
        name: "editorCookie",
        label: "Editor Cookie",
        description:
          "The full Cookie header from an authenticated editor session, including n8n-auth and n8n-browserId when present.",
        placeholder: "n8n-auth=...; n8n-browserId=...",
        secret: true,
        optional: true,
      },
      {
        name: "mcpToken",
        label: "MCP Access Token",
        description:
          "Create this under Settings > Instance-level MCP > Connection details.",
        placeholder: "eyJhbGciOi...",
        secret: true,
        optional: true,
      },
    ],
    exchangeCredentials,
  },
  labelHint: 'e.g. "production", "home"',
  available: true,
};

export const n8nAppInternals = {
  normalizeBaseUrl,
  apiUrl,
  exchangeCredentials,
  validateCredential,
  validateMcpCredential,
};
