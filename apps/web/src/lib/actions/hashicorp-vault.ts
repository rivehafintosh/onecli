"use server";

import { resolveWorkspaceContext } from "@/lib/actions/resolve-user";
import {
  listHashicorpVaultMappings,
  listHashicorpVaultPath,
  getHashicorpVaultSecretMetadata,
  writeHashicorpVaultSecretFields,
  upsertHashicorpVaultMapping,
  deleteHashicorpVaultMapping,
  type UpsertVaultMappingInput,
} from "@onecli/api/services/hashicorp-vault-service";
import {
  withAudit,
  AUDIT_ACTIONS,
  AUDIT_SERVICES,
} from "@onecli/api/services/audit-service";

export const getHashicorpVaultMappings = async () => {
  const { workspaceId } = await resolveWorkspaceContext();
  return listHashicorpVaultMappings(workspaceId);
};

export const browseHashicorpVaultPath = async (path: string) => {
  const { workspaceId } = await resolveWorkspaceContext();
  return listHashicorpVaultPath(workspaceId, path);
};

export const getHashicorpVaultPathMetadata = async (path: string) => {
  const { workspaceId } = await resolveWorkspaceContext();
  return getHashicorpVaultSecretMetadata(workspaceId, path);
};

export const writeHashicorpVaultFields = async (
  path: string,
  fields: Record<string, string>,
) => {
  const { userId, userEmail, workspaceId } = await resolveWorkspaceContext();
  return withAudit(
    () => writeHashicorpVaultSecretFields(workspaceId, path, fields),
    () => ({
      workspaceId,
      userId,
      userEmail,
      action: AUDIT_ACTIONS.UPDATE,
      service: AUDIT_SERVICES.SECRET,
      metadata: {
        source: "hashicorp-vault",
        path,
        fields: Object.keys(fields),
      },
    }),
  );
};

export const saveHashicorpVaultMapping = async (
  input: UpsertVaultMappingInput,
) => {
  const { userId, userEmail, workspaceId } = await resolveWorkspaceContext();
  return withAudit(
    () => upsertHashicorpVaultMapping(workspaceId, input),
    () => ({
      workspaceId,
      userId,
      userEmail,
      action: AUDIT_ACTIONS.UPDATE,
      service: AUDIT_SERVICES.SECRET,
      metadata: {
        source: "hashicorp-vault",
        hostname: input.hostname,
        path: input.path,
        field: input.field,
      },
    }),
  );
};

export const removeHashicorpVaultMapping = async (
  input: UpsertVaultMappingInput,
) => {
  const { userId, userEmail, workspaceId } = await resolveWorkspaceContext();
  return withAudit(
    () => deleteHashicorpVaultMapping(workspaceId, input),
    () => ({
      workspaceId,
      userId,
      userEmail,
      action: AUDIT_ACTIONS.DELETE,
      service: AUDIT_SERVICES.SECRET,
      metadata: {
        source: "hashicorp-vault",
        hostname: input.hostname,
        path: input.path,
        field: input.field,
      },
    }),
  );
};
