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
  const apiKey = fields.apiKey!;
  const response = await fetch(apiUrl(baseUrl, "/api/v1/workflows?limit=1"), {
    headers: { "X-N8N-API-KEY": apiKey },
  });

  if (!response.ok) {
    throw new Error(
      `Could not authenticate with the n8n API (${response.status} ${response.statusText})`,
    );
  }

  const instanceUrl = baseUrl.toString().replace(/\/$/, "");
  return {
    credentials: {
      access_token: apiKey,
      apiKey,
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
};
