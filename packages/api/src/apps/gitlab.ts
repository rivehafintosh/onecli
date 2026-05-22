import type { AppDefinition } from "./types";

export const gitlab: AppDefinition = {
  id: "gitlab",
  name: "GitLab",
  icon: "/icons/gitlab.svg",
  description: "Projects, merge requests, issues, pipelines, and repositories.",
  connectionMethod: {
    type: "oauth",
    defaultScopes: ["read_user", "api", "read_repository", "write_repository"],
    permissions: [
      {
        scope: "read_user",
        name: "Profile",
        description: "Read your GitLab profile and account identity",
        access: "read",
      },
      {
        scope: "read_repository",
        name: "Read repositories",
        description: "Clone and read repository contents",
        access: "read",
      },
      {
        scope: "write_repository",
        name: "Write repositories",
        description: "Push changes to repositories",
        access: "write",
      },
      {
        scope: "api",
        name: "GitLab API",
        description: "Manage projects, issues, merge requests, and pipelines",
        access: "write",
      },
    ],
    buildAuthUrl: ({ appCredentials, redirectUri, scopes, state }) => {
      const baseUrl =
        appCredentials.baseUrl?.replace(/\/+$/, "") || "https://gitlab.com";
      const url = new URL(`${baseUrl}/oauth/authorize`);
      url.searchParams.set("client_id", appCredentials.clientId!);
      url.searchParams.set("redirect_uri", redirectUri);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("scope", scopes.join(" "));
      url.searchParams.set("state", state);
      return url.toString();
    },
    exchangeCode: async ({ appCredentials, callbackParams, redirectUri }) => {
      const baseUrl =
        appCredentials.baseUrl?.replace(/\/+$/, "") || "https://gitlab.com";
      const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          client_id: appCredentials.clientId!,
          client_secret: appCredentials.clientSecret!,
          code: callbackParams.code!,
          grant_type: "authorization_code",
          redirect_uri: redirectUri,
        }),
      });

      if (!tokenRes.ok) {
        throw new Error(
          `GitLab token exchange failed: ${tokenRes.status} ${tokenRes.statusText}`,
        );
      }

      const tokenData = (await tokenRes.json()) as {
        access_token?: string;
        refresh_token?: string;
        scope?: string;
        token_type?: string;
        expires_in?: number;
        created_at?: number;
        error?: string;
        error_description?: string;
      };

      if (tokenData.error || !tokenData.access_token) {
        throw new Error(
          tokenData.error_description ?? "Failed to exchange code for token",
        );
      }

      const credentials: Record<string, unknown> = {
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token,
        token_type: tokenData.token_type,
        expires_in: tokenData.expires_in,
        created_at: tokenData.created_at,
        base_url: baseUrl,
      };
      const scopes = tokenData.scope?.split(" ").filter(Boolean) ?? [];

      let metadata: Record<string, unknown> | undefined;
      const userRes = await fetch(`${baseUrl}/api/v4/user`, {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });

      if (userRes.ok) {
        const user = (await userRes.json()) as {
          username?: string;
          name?: string;
          avatar_url?: string;
          web_url?: string;
        };
        metadata = {
          username: user.username,
          name: user.name,
          avatarUrl: user.avatar_url,
          profileUrl: user.web_url,
          baseUrl,
        };
      }

      return { credentials, scopes, metadata };
    },
  },
  available: true,
  configurable: {
    hint: "Create an OAuth application in GitLab with the redirect URI shown here.",
    fields: [
      {
        name: "clientId",
        label: "Application ID",
        placeholder: "GitLab application ID",
      },
      {
        name: "clientSecret",
        label: "Secret",
        placeholder: "GitLab application secret",
        secret: true,
      },
    ],
    envDefaults: {
      clientId: "GITLAB_CLIENT_ID",
      clientSecret: "GITLAB_CLIENT_SECRET",
    },
  },
};
