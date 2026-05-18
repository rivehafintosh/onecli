import { db, Prisma } from "@onecli/db";
import { getCrypto } from "../providers";
import { ServiceError } from "./errors";
import type { ResourceScope } from "./resource-scope";
import { scopeWhere, scopeCreate, scopeOwnership } from "./resource-scope";
import {
  detectAnthropicAuthMode,
  detectOpenaiAuthMode,
  isHeaderInjection,
  isParamInjection,
  parseOpenaiAuthJson,
  parseOpenaiOAuthJson,
  type CreateSecretInput,
  type UpdateSecretInput,
} from "../validations/secret";

const normalizeOpenaiValue = (
  raw: string,
): { value: string; hostPattern: string } => {
  let value = raw;
  const authJson = parseOpenaiAuthJson(value);
  if (authJson?.mode === "api-key" && authJson.apiKey) {
    value = authJson.apiKey;
  }
  const hostPattern =
    detectOpenaiAuthMode(value) === "oauth" ? "chatgpt.com" : "api.openai.com";
  return { value, hostPattern };
};

const SECRET_TYPE_LABELS: Record<string, string> = {
  anthropic: "Anthropic API Key",
  openai: "OpenAI",
  generic: "Generic Secret",
};

const HASHICORP_VAULT_PROVIDER = "hashicorp-vault";

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

interface HashicorpVaultConnectionData {
  mappings?: unknown;
}

const buildPreview = (plaintext: string): string => {
  if (plaintext.length <= 8) return "•".repeat(plaintext.length);
  return `${plaintext.slice(0, 4)}${"•".repeat(8)}${plaintext.slice(-4)}`;
};

const buildInjectionConfig = (
  config: CreateSecretInput["injectionConfig"],
): Prisma.InputJsonValue | typeof Prisma.JsonNull => {
  if (!config) return Prisma.JsonNull;
  if (isParamInjection(config)) {
    return {
      paramName: config.paramName.trim(),
      paramFormat: config.paramFormat?.trim() || "{value}",
    } as Prisma.InputJsonValue;
  }
  if (isHeaderInjection(config)) {
    return {
      headerName: config.headerName.trim(),
      valueFormat: config.valueFormat?.trim() || "{value}",
    } as Prisma.InputJsonValue;
  }
  return Prisma.JsonNull;
};

const buildMetadata = (
  type: string,
  value: string,
): Prisma.InputJsonValue | typeof Prisma.JsonNull => {
  if (type === "anthropic") {
    return {
      authMode: detectAnthropicAuthMode(value) ?? "api-key",
    } as Prisma.InputJsonValue;
  }
  if (type === "openai") {
    const authMode = detectOpenaiAuthMode(value);
    const parsed = authMode === "oauth" ? parseOpenaiOAuthJson(value) : null;
    return {
      authMode,
      ...(parsed ? { accountId: parsed.tokens.account_id ?? null } : {}),
    } as Prisma.InputJsonValue;
  }
  return Prisma.JsonNull;
};

const buildOnePasswordMetadata = (
  type: string,
  opDisplay: CreateSecretInput["opDisplay"],
): Prisma.InputJsonValue | typeof Prisma.JsonNull => {
  const meta: Record<string, unknown> = {};
  // LLM keys resolved from 1Password are always API-key mode (no value to inspect, no OAuth).
  if (type === "anthropic" || type === "openai") meta.authMode = "api-key";
  if (opDisplay) meta.opDisplay = opDisplay;
  return Object.keys(meta).length > 0
    ? (meta as Prisma.InputJsonValue)
    : Prisma.JsonNull;
};

export type { CreateSecretInput, UpdateSecretInput };

export const listSecrets = async (scope: ResourceScope) => {
  const [secrets, vaultConnection] = await Promise.all([
    db.secret.findMany({
      where: scopeWhere(scope),
      select: {
        id: true,
        name: true,
        type: true,
        valueSource: true,
        opRef: true,
        hostPattern: true,
        pathPattern: true,
        injectionConfig: true,
        metadata: true,
        isPlatform: true,
        scope: true,
        createdAt: true,
      },
      orderBy: { createdAt: "desc" },
    }),
    db.vaultConnection.findFirst({
      where: {
        projectId: scope.projectId,
        provider: HASHICORP_VAULT_PROVIDER,
        status: "connected",
      },
      select: {
        connectionData: true,
        updatedAt: true,
      },
    }),
  ]);

  const dbSecrets = secrets.map((s) => ({
    ...s,
    typeLabel: SECRET_TYPE_LABELS[s.type] ?? s.type,
    source: "db" as const,
  }));

  const vaultSecrets = await listHashicorpVaultSecretReferences(
    vaultConnection?.connectionData,
    vaultConnection?.updatedAt,
  );

  return [...dbSecrets, ...vaultSecrets];
};

const listHashicorpVaultSecretReferences = async (
  connectionData: Prisma.JsonValue | null | undefined,
  updatedAt: Date | undefined,
) => {
  const data = await decryptHashicorpConnectionData(connectionData);
  const mappings = Array.isArray(data?.mappings) ? data.mappings : [];

  return mappings.flatMap((mapping, index) => {
    if (!isVaultCredentialMapping(mapping)) return [];

    const hostname = mapping.hostname.trim();
    const path = mapping.path.trim();
    const field = mapping.field.trim();
    const type = llmSecretTypeForHost(hostname) ?? "generic";

    return [
      {
        id: `vault:${HASHICORP_VAULT_PROVIDER}:${index}:${hostname}:${path}:${field}`,
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

export const createSecret = async (
  scope: ResourceScope,
  input: CreateSecretInput,
) => {
  const name = input.name.trim();
  if (!name || name.length > 255) {
    throw new ServiceError(
      "BAD_REQUEST",
      "Name must be between 1 and 255 characters",
    );
  }

  let hostPattern = input.hostPattern.trim();
  if (!hostPattern)
    throw new ServiceError("BAD_REQUEST", "Host pattern is required");

  if (input.type === "generic") {
    const config = input.injectionConfig;
    const hasHeader = isHeaderInjection(config) && config.headerName.trim();
    const hasParam = isParamInjection(config) && config.paramName.trim();
    if (!hasHeader && !hasParam) {
      throw new ServiceError(
        "BAD_REQUEST",
        "Header name or parameter name is required for generic secrets",
      );
    }
  }

  const pathPattern = input.pathPattern?.trim() || null;
  const injectionConfig =
    input.type === "generic"
      ? buildInjectionConfig(input.injectionConfig)
      : Prisma.JsonNull;

  // Default to "inline" so existing callers and API clients that omit
  // valueSource keep storing the value in Postgres exactly as before.
  const valueSource = input.valueSource ?? "inline";

  // ── Value resolved from 1Password at request time (nothing stored in PG) ──
  if (valueSource === "onepassword") {
    if (!input.opRef) {
      throw new ServiceError("BAD_REQUEST", "Select a 1Password field");
    }
    // LLM keys from 1Password are treated as plain API keys on their fixed host.
    if (input.type === "anthropic") hostPattern = "api.anthropic.com";
    if (input.type === "openai") hostPattern = "api.openai.com";

    return db.secret.create({
      data: {
        name,
        type: input.type,
        valueSource: "onepassword",
        encryptedValue: null,
        opRef: input.opRef,
        hostPattern,
        pathPattern,
        injectionConfig,
        metadata: buildOnePasswordMetadata(input.type, input.opDisplay),
        ...scopeCreate(scope),
      },
      select: {
        id: true,
        name: true,
        type: true,
        valueSource: true,
        opRef: true,
        hostPattern: true,
        pathPattern: true,
        createdAt: true,
      },
    });
  }

  // ── Inline value (encrypted at rest) ──
  let value = (input.value ?? "").trim();
  if (!value) throw new ServiceError("BAD_REQUEST", "Secret value is required");

  if (input.type === "openai") {
    const normalized = normalizeOpenaiValue(value);
    value = normalized.value;
    hostPattern = normalized.hostPattern;
  }

  const secret = await db.secret.create({
    data: {
      name,
      type: input.type,
      valueSource: "inline",
      encryptedValue: await getCrypto().encrypt(value),
      hostPattern,
      pathPattern,
      injectionConfig,
      metadata: buildMetadata(input.type, value),
      ...scopeCreate(scope),
    },
    select: {
      id: true,
      name: true,
      type: true,
      valueSource: true,
      opRef: true,
      hostPattern: true,
      pathPattern: true,
      createdAt: true,
    },
  });

  return { ...secret, preview: buildPreview(value) };
};

export const deleteSecret = async (scope: ResourceScope, secretId: string) => {
  const secret = await db.secret.findFirst({
    where: scopeOwnership(scope, secretId),
    select: { id: true },
  });

  if (!secret) throw new ServiceError("NOT_FOUND", "Secret not found");

  await db.secret.delete({ where: { id: secretId } });
};

export const updateSecret = async (
  scope: ResourceScope,
  secretId: string,
  input: UpdateSecretInput,
) => {
  const secret = await db.secret.findFirst({
    where: scopeOwnership(scope, secretId),
    select: { id: true, type: true, isPlatform: true },
  });

  if (!secret) throw new ServiceError("NOT_FOUND", "Secret not found");

  if (secret.isPlatform) {
    const hasNonValueFields =
      input.name !== undefined ||
      input.hostPattern !== undefined ||
      input.pathPattern !== undefined ||
      input.injectionConfig !== undefined;
    if (hasNonValueFields)
      throw new ServiceError(
        "FORBIDDEN",
        "Only the value can be updated on platform secrets",
      );
    if (input.value === undefined && input.opRef === undefined)
      throw new ServiceError("BAD_REQUEST", "Value is required");
  }

  const data: Record<string, unknown> = {};

  if (input.name !== undefined) {
    const name = input.name.trim();
    if (!name) throw new ServiceError("BAD_REQUEST", "Name is required");
    data.name = name;
  }

  if (input.valueSource === "onepassword") {
    // Switch to / update a value resolved from 1Password.
    if (!input.opRef)
      throw new ServiceError("BAD_REQUEST", "Select a 1Password field");
    data.valueSource = "onepassword";
    data.encryptedValue = null;
    data.opRef = input.opRef;
    if (secret.type === "anthropic") data.hostPattern = "api.anthropic.com";
    if (secret.type === "openai") data.hostPattern = "api.openai.com";
    data.metadata = buildOnePasswordMetadata(secret.type, input.opDisplay);
    if (secret.isPlatform) data.isPlatform = false;
  } else if (input.value !== undefined) {
    let value = input.value.trim();
    if (!value)
      throw new ServiceError("BAD_REQUEST", "Secret value is required");

    if (secret.type === "openai") {
      const normalized = normalizeOpenaiValue(value);
      value = normalized.value;
      data.hostPattern = normalized.hostPattern;
    }

    data.valueSource = "inline";
    data.encryptedValue = await getCrypto().encrypt(value);
    data.opRef = null;

    if (secret.isPlatform) {
      data.isPlatform = false;
    }

    if (secret.type === "anthropic" || secret.type === "openai") {
      data.metadata = buildMetadata(secret.type, value);
    }
  }

  if (input.hostPattern !== undefined) {
    const hostPattern = input.hostPattern.trim();
    if (!hostPattern)
      throw new ServiceError("BAD_REQUEST", "Host pattern is required");
    data.hostPattern = hostPattern;
  }

  if (input.pathPattern !== undefined) {
    data.pathPattern = input.pathPattern?.trim() || null;
  }

  if (input.injectionConfig !== undefined && secret.type === "generic") {
    data.injectionConfig = buildInjectionConfig(input.injectionConfig);
  }

  if (Object.keys(data).length === 0) {
    throw new ServiceError("BAD_REQUEST", "No fields to update");
  }

  await db.secret.update({ where: { id: secretId }, data });
};
