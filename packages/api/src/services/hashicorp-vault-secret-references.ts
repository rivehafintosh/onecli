import { Prisma, db } from "@onecli/db";
import { getCrypto } from "../providers";
import { ServiceError } from "./errors";

export const HASHICORP_VAULT_PROVIDER = "hashicorp-vault";

interface VaultCredentialMapping {
  hostname?: unknown;
  path?: unknown;
  field?: unknown;
  path_pattern?: unknown;
  pathPattern?: unknown;
  path_pattern_field?: unknown;
  username_field?: unknown;
}

interface NormalizedVaultCredentialMapping {
  hostname: string;
  path: string;
  field: string;
  pathPattern: string | null;
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

const getPathPattern = (mapping: VaultCredentialMapping) => {
  const value = mapping.path_pattern ?? mapping.pathPattern;
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : null;
};

const assertValidHostPattern = (value: string) => {
  if (!value) {
    throw new ServiceError("BAD_REQUEST", "Host pattern is required");
  }
  if (value.includes("://")) {
    throw new ServiceError(
      "BAD_REQUEST",
      "Enter a hostname, not a URL (remove http:// or https://)",
    );
  }
  if (value.includes("/")) {
    throw new ServiceError(
      "BAD_REQUEST",
      "Enter a hostname only, not a path (use the path pattern field for paths)",
    );
  }
  if (value.includes(" ")) {
    throw new ServiceError(
      "BAD_REQUEST",
      "Host pattern must not contain spaces",
    );
  }
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
        pathPattern: getPathPattern(mapping),
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

const encryptHashicorpConnectionData = async (
  data: HashicorpVaultConnectionData,
  encrypt: boolean,
): Promise<Prisma.InputJsonValue> => {
  if (!encrypt) return data as Prisma.InputJsonValue;
  return {
    encrypted: await getCrypto().encrypt(JSON.stringify(data)),
  } as Prisma.InputJsonValue;
};

export const updateHashicorpVaultSecretReference = async (
  projectId: string | undefined,
  secretId: string,
  input: {
    hostPattern?: string;
    pathPattern?: string | null;
  },
) => {
  const reference = parseVaultSecretId(secretId);
  if (reference?.provider !== HASHICORP_VAULT_PROVIDER) return false;
  if (!projectId) {
    throw new ServiceError(
      "BAD_REQUEST",
      "HashiCorp Vault mappings are only available per project",
    );
  }

  const vaultConnection = await db.vaultConnection.findFirst({
    where: {
      projectId,
      provider: HASHICORP_VAULT_PROVIDER,
      status: "connected",
    },
    select: {
      id: true,
      connectionData: true,
    },
  });
  if (!vaultConnection) return false;

  const data = await decryptHashicorpConnectionData(
    vaultConnection.connectionData,
  );
  const mappings = Array.isArray(data?.mappings) ? data.mappings : [];
  const mappingIndex = mappings.findIndex(
    (mapping) =>
      isVaultCredentialMapping(mapping) &&
      mapping.hostname.trim() === reference.hostname &&
      mapping.path.trim() === reference.path &&
      mapping.field.trim() === reference.field,
  );
  if (mappingIndex < 0 || !data) return false;

  const current = mappings[mappingIndex] as VaultCredentialMapping;
  const nextHostname =
    input.hostPattern !== undefined
      ? input.hostPattern.trim()
      : reference.hostname;
  const next: VaultCredentialMapping = {
    ...current,
    hostname: nextHostname,
  };
  assertValidHostPattern(nextHostname);

  const nextPathPattern =
    input.pathPattern !== undefined
      ? input.pathPattern?.trim() || null
      : getPathPattern(current);
  delete next.pathPattern;
  if (nextPathPattern) {
    next.path_pattern = nextPathPattern;
  } else {
    delete next.path_pattern;
  }

  data.mappings = mappings.map((mapping, index) =>
    index === mappingIndex ? next : mapping,
  );

  const encrypted =
    !!vaultConnection.connectionData &&
    typeof vaultConnection.connectionData === "object" &&
    !Array.isArray(vaultConnection.connectionData) &&
    typeof vaultConnection.connectionData["encrypted"] === "string";

  await db.vaultConnection.update({
    where: { id: vaultConnection.id },
    data: {
      connectionData: await encryptHashicorpConnectionData(data, encrypted),
    },
  });

  return true;
};

export const deleteHashicorpVaultSecretReference = async (
  projectId: string | undefined,
  secretId: string,
) => {
  const reference = parseVaultSecretId(secretId);
  if (reference?.provider !== HASHICORP_VAULT_PROVIDER) return false;
  if (!projectId) {
    throw new ServiceError(
      "BAD_REQUEST",
      "HashiCorp Vault mappings are only available per project",
    );
  }

  const vaultConnection = await db.vaultConnection.findFirst({
    where: {
      projectId,
      provider: HASHICORP_VAULT_PROVIDER,
      status: "connected",
    },
    select: {
      id: true,
      connectionData: true,
    },
  });
  if (!vaultConnection) return false;

  const data = await decryptHashicorpConnectionData(
    vaultConnection.connectionData,
  );
  const mappings = Array.isArray(data?.mappings) ? data.mappings : [];
  const nextMappings = mappings.filter(
    (mapping) =>
      !(
        isVaultCredentialMapping(mapping) &&
        mapping.hostname.trim() === reference.hostname &&
        mapping.path.trim() === reference.path &&
        mapping.field.trim() === reference.field
      ),
  );
  if (!data || nextMappings.length === mappings.length) return false;

  data.mappings = nextMappings;

  const encrypted =
    !!vaultConnection.connectionData &&
    typeof vaultConnection.connectionData === "object" &&
    !Array.isArray(vaultConnection.connectionData) &&
    typeof vaultConnection.connectionData["encrypted"] === "string";

  await db.vaultConnection.update({
    where: { id: vaultConnection.id },
    data: {
      connectionData: await encryptHashicorpConnectionData(data, encrypted),
    },
  });

  return true;
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
