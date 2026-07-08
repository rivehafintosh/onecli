import { getCrypto } from "@onecli/api/providers";
import { ServiceError } from "@onecli/api/services/errors";
import { db, type Prisma } from "@onecli/db";

const PROVIDER = "hashicorp-vault";

export interface VaultMapping {
  hostname: string;
  path: string;
  field: string;
  username_field?: string;
}

interface ConnectionData {
  address: string;
  token: string;
  mount: string;
  path_prefix: string;
  namespace?: string | null;
  kv_version: number;
  mappings: VaultMapping[];
}

export interface MappingInput {
  hostname: string;
  path: string;
  field: string;
  usernameField?: string;
}

const normalizePath = (value: string) =>
  value
    .trim()
    .split("/")
    .map((part) => part.trim())
    .filter(Boolean)
    .join("/");

const required = (value: string, field: string) => {
  const result = value.trim();
  if (!result) throw new ServiceError("BAD_REQUEST", `${field} is required`);
  return result;
};

const normalizeMapping = (input: MappingInput): VaultMapping => ({
  hostname: required(input.hostname, "hostname"),
  path: normalizePath(input.path),
  field: required(input.field, "field"),
  ...(input.usernameField?.trim()
    ? { username_field: input.usernameField.trim() }
    : {}),
});

const load = async (projectId: string): Promise<ConnectionData> => {
  const row = await db.vaultConnection.findFirst({
    where: { projectId, provider: PROVIDER, status: "connected" },
    select: { connectionData: true },
  });
  if (!row?.connectionData) {
    throw new ServiceError("NOT_FOUND", "HashiCorp Vault is not connected");
  }
  const value = row.connectionData;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new ServiceError("BAD_REQUEST", "Invalid Vault connection data");
  }
  const encrypted = value["encrypted"];
  const data =
    typeof encrypted === "string"
      ? (JSON.parse(await getCrypto().decrypt(encrypted)) as ConnectionData)
      : (value as unknown as ConnectionData);
  return { ...data, mappings: data.mappings ?? [] };
};

const save = async (projectId: string, data: ConnectionData) => {
  const encrypted = await getCrypto().encrypt(JSON.stringify(data));
  await db.vaultConnection.update({
    where: { projectId_provider: { projectId, provider: PROVIDER } },
    data: {
      connectionData: { encrypted } satisfies Prisma.InputJsonValue,
    },
  });
};

const target = (data: ConnectionData, logicalPath: string) => {
  const colon = logicalPath.indexOf(":");
  if (colon > 0) {
    return {
      mount: logicalPath.slice(0, colon),
      path: normalizePath(logicalPath.slice(colon + 1)),
    };
  }
  const parts = normalizePath(logicalPath).split("/").filter(Boolean);
  if (parts[0] === data.mount && parts.length > 1) {
    return { mount: parts[0], path: parts.slice(1).join("/") };
  }
  return { mount: data.mount, path: normalizePath(logicalPath) };
};

const vaultRequest = async <T>(
  data: ConnectionData,
  method: string,
  path: string,
  body?: unknown,
): Promise<T> => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(
      new URL(`/v1/${path.replace(/^\/+/, "")}`, data.address),
      {
        method,
        headers: {
          "X-Vault-Token": data.token,
          ...(data.namespace ? { "X-Vault-Namespace": data.namespace } : {}),
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      },
    );
    const text = await response.text();
    if (!response.ok) {
      throw new ServiceError(
        "BAD_REQUEST",
        `Vault request failed: ${response.status} ${text}`,
      );
    }
    return (text ? JSON.parse(text) : {}) as T;
  } finally {
    clearTimeout(timeout);
  }
};

const readFields = async (data: ConnectionData, logicalPath: string) => {
  const location = target(data, logicalPath);
  const apiPath =
    data.kv_version === 2
      ? `${location.mount}/data/${location.path}`
      : `${location.mount}/${location.path}`;
  const result = await vaultRequest<{ data?: unknown }>(data, "GET", apiPath);
  const raw =
    data.kv_version === 2 &&
    result.data &&
    typeof result.data === "object" &&
    !Array.isArray(result.data)
      ? (result.data as { data?: unknown }).data
      : result.data;
  return raw && typeof raw === "object" && !Array.isArray(raw)
    ? (raw as Record<string, unknown>)
    : {};
};

export const listMappings = async (projectId: string) =>
  (await load(projectId)).mappings;

export const setMapping = async (projectId: string, input: MappingInput) => {
  const data = await load(projectId);
  const mapping = normalizeMapping(input);
  data.mappings = [
    ...data.mappings.filter(
      (item) =>
        !(
          item.hostname === mapping.hostname &&
          item.path === mapping.path &&
          item.field === mapping.field
        ),
    ),
    mapping,
  ];
  await save(projectId, data);
  return data.mappings;
};

export const deleteMapping = async (projectId: string, input: MappingInput) => {
  const data = await load(projectId);
  const mapping = normalizeMapping(input);
  data.mappings = data.mappings.filter(
    (item) =>
      item.hostname !== mapping.hostname ||
      item.path !== mapping.path ||
      item.field !== mapping.field,
  );
  await save(projectId, data);
  return data.mappings;
};

export const listPath = async (projectId: string, logicalPath: string) => {
  const data = await load(projectId);
  const location = target(data, logicalPath);
  const apiPath =
    data.kv_version === 2
      ? `${location.mount}/metadata/${location.path}`
      : `${location.mount}/${location.path}`;
  const result = await vaultRequest<{ data?: { keys?: unknown } }>(
    data,
    "LIST",
    apiPath,
  );
  const base = normalizePath(logicalPath);
  return (Array.isArray(result.data?.keys) ? result.data.keys : [])
    .filter((key): key is string => typeof key === "string")
    .map((key) => ({
      name: key.replace(/\/$/, ""),
      path: [base, key.replace(/\/$/, "")].filter(Boolean).join("/"),
      folder: key.endsWith("/"),
    }));
};

export const metadata = async (projectId: string, logicalPath: string) => {
  const data = await load(projectId);
  const path = normalizePath(logicalPath);
  return {
    path,
    fields: Object.keys(await readFields(data, path)).sort(),
    mappings: data.mappings.filter((mapping) => mapping.path === path),
  };
};

export const writeFields = async (
  projectId: string,
  logicalPath: string,
  fields: Record<string, string>,
) => {
  const data = await load(projectId);
  const path = normalizePath(logicalPath);
  const location = target(data, path);
  const next = {
    ...(await readFields(data, path).catch(() => ({}))),
    ...fields,
  };
  const apiPath =
    data.kv_version === 2
      ? `${location.mount}/data/${location.path}`
      : `${location.mount}/${location.path}`;
  await vaultRequest(
    data,
    "POST",
    apiPath,
    data.kv_version === 2 ? { data: next } : next,
  );
  return metadata(projectId, path);
};
