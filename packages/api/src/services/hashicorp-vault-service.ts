import http from "node:http";
import https from "node:https";
import { URL } from "node:url";
import { db, Prisma } from "@onecli/db";
import { getCrypto } from "../providers";
import { ServiceError } from "./errors";

const PROVIDER = "hashicorp-vault";

export interface CredentialMapping {
  hostname: string;
  path: string;
  field: string;
  username_field?: string;
}

interface HashicorpVaultConnectionData {
  address: string;
  token: string;
  mount: string;
  path_prefix: string;
  namespace?: string | null;
  ca_cert_pem?: string | null;
  kv_version: number;
  mappings: CredentialMapping[];
}

export interface VaultPathEntry {
  name: string;
  path: string;
  folder: boolean;
}

export interface VaultSecretMetadata {
  path: string;
  fields: string[];
  mappings: CredentialMapping[];
}

export interface UpsertVaultMappingInput {
  hostname: string;
  path: string;
  field: string;
  usernameField?: string;
}

export const listHashicorpVaultMappings = async (workspaceId: string) => {
  const data = await loadHashicorpConnection(workspaceId);
  return data.mappings;
};

export const listHashicorpVaultPath = async (
  workspaceId: string,
  path = "",
): Promise<VaultPathEntry[]> => {
  const data = await loadHashicorpConnection(workspaceId);
  const logicalPath = normalizeVaultPath(path);
  const target = vaultTarget(data, logicalPath);
  const apiPath =
    data.kv_version === 2
      ? joinVaultPath(target.mount, "metadata", target.path)
      : joinVaultPath(target.mount, target.path);
  const body = await vaultRequest<{ data?: { keys?: unknown } }>(
    data,
    "LIST",
    apiPath,
  );
  const keys = Array.isArray(body.data?.keys) ? body.data.keys : [];
  return keys
    .filter((key): key is string => typeof key === "string" && key.length > 0)
    .map((key) => {
      const folder = key.endsWith("/");
      const name = folder ? key.slice(0, -1) : key;
      return {
        name,
        folder,
        path: joinLogicalPath(logicalPath, name),
      };
    });
};

export const getHashicorpVaultSecretMetadata = async (
  workspaceId: string,
  path: string,
): Promise<VaultSecretMetadata> => {
  const data = await loadHashicorpConnection(workspaceId);
  const logicalPath = normalizeVaultPath(path);
  const target = vaultTarget(data, logicalPath);
  const secret = await readSecretData(data, target);
  return {
    path: logicalPath,
    fields: Object.keys(secret).sort(),
    mappings: data.mappings.filter((mapping) => mapping.path === logicalPath),
  };
};

export const writeHashicorpVaultSecretFields = async (
  workspaceId: string,
  path: string,
  fields: Record<string, string>,
): Promise<VaultSecretMetadata> => {
  const data = await loadHashicorpConnection(workspaceId);
  const logicalPath = normalizeVaultPath(path);
  const target = vaultTarget(data, logicalPath);
  const cleanFields = Object.fromEntries(
    Object.entries(fields)
      .map(([key, value]) => [key.trim(), value] as const)
      .filter(([key]) => key.length > 0),
  );
  if (Object.keys(cleanFields).length === 0) {
    throw new ServiceError("BAD_REQUEST", "At least one field is required");
  }

  const apiPath =
    data.kv_version === 2
      ? joinVaultPath(target.mount, "data", target.path)
      : joinVaultPath(target.mount, target.path);
  const existing = await readSecretData(data, target).catch(() => null);
  if (existing) {
    const next = { ...existing, ...cleanFields };
    await vaultRequest(
      data,
      "POST",
      apiPath,
      data.kv_version === 2 ? { data: next } : next,
    );
  } else if (data.kv_version === 2) {
    await vaultRequest(data, "PATCH", apiPath, { data: cleanFields }).catch(
      () => vaultRequest(data, "POST", apiPath, { data: cleanFields }),
    );
  } else {
    await vaultRequest(data, "POST", apiPath, cleanFields);
  }
  return getHashicorpVaultSecretMetadata(workspaceId, logicalPath).catch(
    () => ({
      path: logicalPath,
      fields: Object.keys(cleanFields).sort(),
      mappings: data.mappings.filter((mapping) => mapping.path === logicalPath),
    }),
  );
};

export const upsertHashicorpVaultMapping = async (
  workspaceId: string,
  input: UpsertVaultMappingInput,
) => {
  const data = await loadHashicorpConnection(workspaceId);
  const mapping = normalizeMapping(input);
  const nextMappings = [
    ...data.mappings.filter(
      (existing) =>
        !(
          existing.hostname === mapping.hostname &&
          existing.path === mapping.path &&
          existing.field === mapping.field
        ),
    ),
    mapping,
  ].sort((a, b) => a.hostname.localeCompare(b.hostname));
  await saveHashicorpConnection(workspaceId, {
    ...data,
    mappings: nextMappings,
  });
  return nextMappings;
};

export const deleteHashicorpVaultMapping = async (
  workspaceId: string,
  input: UpsertVaultMappingInput,
) => {
  const data = await loadHashicorpConnection(workspaceId);
  const mapping = normalizeMapping(input);
  const nextMappings = data.mappings.filter(
    (existing) =>
      !(
        existing.hostname === mapping.hostname &&
        existing.path === mapping.path &&
        existing.field === mapping.field
      ),
  );
  await saveHashicorpConnection(workspaceId, {
    ...data,
    mappings: nextMappings,
  });
  return nextMappings;
};

const loadHashicorpConnection = async (
  workspaceId: string,
): Promise<HashicorpVaultConnectionData> => {
  const row = await db.vaultConnection.findFirst({
    where: { workspaceId, provider: PROVIDER, status: "connected" },
    select: { connectionData: true },
  });
  if (!row?.connectionData) {
    throw new ServiceError("NOT_FOUND", "HashiCorp Vault is not connected");
  }

  const data = await decryptConnectionData(row.connectionData);
  return {
    ...data,
    mappings: Array.isArray(data.mappings) ? data.mappings : [],
  };
};

const saveHashicorpConnection = async (
  workspaceId: string,
  data: HashicorpVaultConnectionData,
) => {
  const encrypted = await getCrypto().encrypt(JSON.stringify(data));
  await db.vaultConnection.update({
    where: {
      workspaceId_provider: {
        workspaceId,
        provider: PROVIDER,
      },
    },
    data: {
      connectionData: { encrypted },
    },
  });
};

const decryptConnectionData = async (
  value: Prisma.JsonValue,
): Promise<HashicorpVaultConnectionData> => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ServiceError("BAD_REQUEST", "Invalid Vault connection data");
  }

  const encrypted = value["encrypted"];
  if (typeof encrypted === "string") {
    return JSON.parse(await getCrypto().decrypt(encrypted));
  }

  return value as unknown as HashicorpVaultConnectionData;
};

interface VaultTarget {
  mount: string;
  path: string;
}

const readSecretData = async (
  data: HashicorpVaultConnectionData,
  target: VaultTarget,
): Promise<Record<string, unknown>> => {
  const apiPath =
    data.kv_version === 2
      ? joinVaultPath(target.mount, "data", target.path)
      : joinVaultPath(target.mount, target.path);
  const body = await vaultRequest<{ data?: unknown }>(data, "GET", apiPath);
  const secret = data.kv_version === 2 ? nestedData(body.data) : body.data;
  return secret && typeof secret === "object" && !Array.isArray(secret)
    ? (secret as Record<string, unknown>)
    : {};
};

const nestedData = (value: unknown) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return (value as { data?: unknown }).data;
};

const vaultTarget = (
  data: HashicorpVaultConnectionData,
  logicalPath: string,
): VaultTarget => {
  const colonIndex = logicalPath.indexOf(":");
  if (colonIndex > 0) {
    const mount = logicalPath
      .slice(0, colonIndex)
      .trim()
      .replace(/^\/+|\/+$/g, "");
    const path = logicalPath
      .slice(colonIndex + 1)
      .trim()
      .replace(/^\/+|\/+$/g, "");
    if (mount && !mount.includes("/") && path) {
      return { mount, path };
    }
  }

  const [first, ...rest] = logicalPath.split("/").filter(Boolean);
  if (
    (first === data.mount || first === "kv" || first === "kv-admin") &&
    rest.length > 0
  ) {
    return { mount: first, path: rest.join("/") };
  }
  return { mount: data.mount, path: logicalPath };
};

const vaultRequest = async <T>(
  data: HashicorpVaultConnectionData,
  method: string,
  apiPath: string,
  body?: unknown,
): Promise<T> => {
  const url = new URL(`/v1/${apiPath}`, data.address.replace(/\/+$/, ""));
  const payload = body === undefined ? undefined : JSON.stringify(body);
  const headers: Record<string, string> = {
    "X-Vault-Token": data.token,
    Accept: "application/json",
  };
  if (data.namespace) headers["X-Vault-Namespace"] = data.namespace;
  if (payload !== undefined) headers["Content-Type"] = "application/json";

  const requestOptions: http.RequestOptions | https.RequestOptions = {
    method,
    headers,
    timeout: 15_000,
    ...(url.protocol === "https:" && data.ca_cert_pem
      ? { ca: data.ca_cert_pem }
      : {}),
  };
  const transport = url.protocol === "https:" ? https : http;

  return new Promise((resolve, reject) => {
    const req = transport.request(url, requestOptions, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        if ((res.statusCode ?? 500) < 200 || (res.statusCode ?? 500) >= 300) {
          reject(
            new ServiceError(
              "BAD_REQUEST",
              `Vault request failed: ${res.statusCode} ${text}`,
            ),
          );
          return;
        }
        try {
          resolve((text ? JSON.parse(text) : {}) as T);
        } catch {
          reject(
            new ServiceError("BAD_REQUEST", "Invalid Vault JSON response"),
          );
        }
      });
    });
    req.on("timeout", () => req.destroy(new Error("Vault request timed out")));
    req.on("error", reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
};

const normalizeMapping = (
  input: UpsertVaultMappingInput,
): CredentialMapping => ({
  hostname: requireNonEmpty(input.hostname, "hostname"),
  path: normalizeVaultPath(input.path),
  field: requireNonEmpty(input.field, "field"),
  ...(input.usernameField?.trim()
    ? { username_field: input.usernameField.trim() }
    : {}),
});

const normalizeVaultPath = (path: string) =>
  path
    .trim()
    .split("/")
    .map((part) => part.trim())
    .filter(Boolean)
    .join("/");

const joinLogicalPath = (...parts: string[]) =>
  parts
    .flatMap((part) => part.split("/"))
    .map((part) => part.trim())
    .filter(Boolean)
    .join("/");

const joinVaultPath = (...parts: string[]) => joinLogicalPath(...parts);

const requireNonEmpty = (value: string, name: string) => {
  const trimmed = value.trim();
  if (!trimmed) throw new ServiceError("BAD_REQUEST", `${name} is required`);
  return trimmed;
};
