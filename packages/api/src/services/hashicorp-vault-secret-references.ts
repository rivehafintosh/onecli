import { Prisma, db } from "@onecli/db";
import { getCrypto } from "../providers";

export const HASHICORP_VAULT_PROVIDER = "hashicorp-vault";

interface VaultCredentialMapping {
  hostname?: unknown;
  path?: unknown;
  field?: unknown;
}

interface NormalizedVaultCredentialMapping {
  hostname: string;
  path: string;
  field: string;
}

export interface VaultSecretReference {
  provider: string;
  hostname: string;
  path: string;
  field: string;
}

interface HashicorpVaultConnectionData {
  mappings?: unknown;
}

const SECRET_TYPE_LABELS: Record<string, string> = {
  anthropic: "Anthropic API Key",
  openai: "OpenAI",
  generic: "Generic Secret",
};

export const buildVaultSecretId = ({
  provider,
  hostname,
  path,
  field,
}: VaultSecretReference) =>
  `vault:${provider}:${Buffer.from(
    JSON.stringify({ hostname, path, field }),
  ).toString("base64url")}`;

export const parseVaultSecretId = (id: string): VaultSecretReference | null => {
  const [prefix, provider, encoded, ...rest] = id.split(":");
  if (prefix !== "vault" || !provider || !encoded || rest.length > 0) {
    return null;
  }

  try {
    const value = JSON.parse(Buffer.from(encoded, "base64url").toString());
    if (!isVaultCredentialMapping(value)) return null;
    return {
      provider,
      hostname: value.hostname.trim(),
      path: value.path.trim(),
      field: value.field.trim(),
    };
  } catch {
    return null;
  }
};

export const listHashicorpVaultSecretReferencesForProject = async (
  projectId: string,
) => {
  const vaultConnection = await db.vaultConnection.findFirst({
    where: {
      projectId,
      provider: HASHICORP_VAULT_PROVIDER,
      status: "connected",
    },
    select: {
      connectionData: true,
      updatedAt: true,
    },
  });

  return listHashicorpVaultSecretReferences(
    vaultConnection?.connectionData,
    vaultConnection?.updatedAt,
  );
};

export const listHashicorpVaultSecretReferencesForScope = async (scope: {
  projectId?: string;
}) => {
  if (!scope.projectId) return [];

  const vaultConnection = await db.vaultConnection.findFirst({
    where: {
      projectId: scope.projectId,
      provider: HASHICORP_VAULT_PROVIDER,
      status: "connected",
    },
    select: {
      connectionData: true,
      updatedAt: true,
    },
  });

  return listHashicorpVaultSecretReferences(
    vaultConnection?.connectionData,
    vaultConnection?.updatedAt,
  );
};

const listHashicorpVaultSecretReferences = async (
  connectionData: Prisma.JsonValue | null | undefined,
  updatedAt: Date | undefined,
) => {
  const data = await decryptHashicorpConnectionData(connectionData);
  const mappings = Array.isArray(data?.mappings) ? data.mappings : [];

  return mappings.flatMap((mapping) => {
    if (!isVaultCredentialMapping(mapping)) return [];

    const hostname = mapping.hostname.trim();
    const path = mapping.path.trim();
    const field = mapping.field.trim();
    const type = llmSecretTypeForHost(hostname) ?? "generic";
    const vaultRef = {
      provider: HASHICORP_VAULT_PROVIDER,
      hostname,
      path,
      field,
    };

    return [
      {
        id: buildVaultSecretId(vaultRef),
        name: `${displayNameForHost(hostname)} via Vault`,
        type,
        typeLabel:
          type === "generic"
            ? "Vault Secret"
            : `${SECRET_TYPE_LABELS[type]} via Vault`,
        hostPattern: hostname,
        pathPattern: null,
        injectionConfig: Prisma.JsonNull,
        isPlatform: false,
        scope: "project",
        createdAt: updatedAt ?? new Date(0),
        source: "vault" as const,
        vaultProvider: HASHICORP_VAULT_PROVIDER,
        vaultPath: path,
        vaultField: field,
      },
    ];
  });
};

const decryptHashicorpConnectionData = async (
  connectionData: Prisma.JsonValue | null | undefined,
): Promise<HashicorpVaultConnectionData | null> => {
  if (!connectionData || typeof connectionData !== "object") return null;
  if (Array.isArray(connectionData)) return null;

  const encrypted = connectionData["encrypted"];
  if (typeof encrypted === "string") {
    try {
      return JSON.parse(await getCrypto().decrypt(encrypted));
    } catch {
      return null;
    }
  }

  return connectionData as HashicorpVaultConnectionData;
};

const isVaultCredentialMapping = (
  value: unknown,
): value is NormalizedVaultCredentialMapping => {
  if (!value || typeof value !== "object") return false;
  const mapping = value as VaultCredentialMapping;
  return (
    typeof mapping.hostname === "string" &&
    mapping.hostname.trim().length > 0 &&
    typeof mapping.path === "string" &&
    mapping.path.trim().length > 0 &&
    typeof mapping.field === "string" &&
    mapping.field.trim().length > 0
  );
};

const llmSecretTypeForHost = (hostname: string) => {
  if (hostname === "api.anthropic.com") return "anthropic";
  if (hostname === "api.openai.com") return "openai";
  return null;
};

const displayNameForHost = (hostname: string) => {
  if (hostname === "api.anthropic.com") return "Anthropic";
  if (hostname === "api.openai.com") return "OpenAI";
  return hostname;
};
