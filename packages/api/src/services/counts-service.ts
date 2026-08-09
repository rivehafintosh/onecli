import { db } from "@onecli/db";
import { getCrypto } from "../providers";

const HASHICORP_VAULT_PROVIDER = "hashicorp-vault";

export const getResourceCounts = async (
  projectId: string,
  organizationId?: string,
) => {
  const secretWhere = (type: "generic" | "non-generic") => {
    const typeFilter =
      type === "generic"
        ? { type: "generic" as const }
        : { type: { not: "generic" } };
    if (!organizationId) return { projectId, ...typeFilter };
    return {
      OR: [
        { projectId, ...typeFilter },
        { organizationId, scope: "organization", ...typeFilter },
      ],
    };
  };

  const appWhere = organizationId
    ? {
        OR: [
          { projectId, status: "connected" },
          { organizationId, scope: "organization", status: "connected" },
        ],
      }
    : { projectId, status: "connected" };

  const [agents, apps, llms, secrets, vaultConnection] = await Promise.all([
    db.agent.count({ where: { projectId } }),
    db.appConnection.count({ where: appWhere }),
    db.secret.count({ where: secretWhere("non-generic") }),
    db.secret.count({ where: secretWhere("generic") }),
    db.vaultConnection.findFirst({
      where: {
        projectId,
        provider: HASHICORP_VAULT_PROVIDER,
        status: "connected",
      },
      select: { connectionData: true },
    }),
  ]);

  return {
    agents,
    apps,
    llms: llms + (await countVaultLlmMappings(vaultConnection?.connectionData)),
    secrets,
  };
};

const countVaultLlmMappings = async (connectionData: unknown) => {
  const data = await decryptHashicorpConnectionData(connectionData);
  const mappings = Array.isArray(data?.mappings) ? data.mappings : [];
  return new Set(
    mappings
      .map((mapping) =>
        mapping && typeof mapping === "object"
          ? (mapping as { hostname?: unknown }).hostname
          : null,
      )
      .filter(
        (hostname): hostname is string =>
          hostname === "api.anthropic.com" || hostname === "api.openai.com",
      ),
  ).size;
};

const decryptHashicorpConnectionData = async (connectionData: unknown) => {
  if (!connectionData || typeof connectionData !== "object") return null;
  if (Array.isArray(connectionData)) return null;

  const encrypted = (connectionData as { encrypted?: unknown }).encrypted;
  if (typeof encrypted === "string") {
    try {
      return JSON.parse(await getCrypto().decrypt(encrypted)) as {
        mappings?: unknown;
      };
    } catch {
      return null;
    }
  }

  return connectionData as { mappings?: unknown };
};
