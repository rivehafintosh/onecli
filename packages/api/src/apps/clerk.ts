import type { AppDefinition } from "./types";

export const clerk: AppDefinition = {
  id: "clerk",
  name: "Clerk",
  icon: "/icons/clerk.svg",
  description:
    "Manage users, organizations, sessions, and authentication with Clerk.",
  connectionMethod: {
    type: "api_key",
    fields: [
      {
        name: "secretKey",
        label: "Secret Key",
        description:
          "Your Clerk Backend API secret key. Find it in the Clerk Dashboard under API Keys.",
        placeholder: "sk_test_...",
        helpUrl: "https://dashboard.clerk.com/last-active?path=api-keys",
        helpLabel: "Open Clerk API Keys",
      },
    ],
    resolveMetadata: async (fields) => {
      try {
        const res = await fetch("https://api.clerk.com/v1/instance", {
          headers: { Authorization: `Bearer ${fields.secretKey}` },
        });
        if (res.ok) {
          const instance = (await res.json()) as {
            id?: string;
            environment_type?: string;
          };
          const name = instance.environment_type
            ? `${instance.environment_type} instance`
            : instance.id;
          if (name) {
            return {
              name,
              username: instance.id ?? name,
            };
          }
        }
      } catch {
        // Non-fatal
      }
      return null;
    },
  },
  labelHint: 'e.g. "production", "staging"',
  available: true,
};
