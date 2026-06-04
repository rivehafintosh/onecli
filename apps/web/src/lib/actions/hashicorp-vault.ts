"use server";

import { resolveProjectContext } from "@/lib/actions/resolve-user";
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
  const { projectId } = await resolveProjectContext();
  return listHashicorpVaultMappings(projectId);
};

export const browseHashicorpVaultPath = async (path: string) => {
  const { projectId } = await resolveProjectContext();
  return listHashicorpVaultPath(projectId, path);
};

export const getHashicorpVaultPathMetadata = async (path: string) => {
  const { projectId } = await resolveProjectContext();
  return getHashicorpVaultSecretMetadata(projectId, path);
};

export const writeHashicorpVaultFields = async (
  path: string,
  fields: Record<string, string>,
) => {
  const { userId, userEmail, projectId } = await resolveProjectContext();
  return withAudit(
    () => writeHashicorpVaultSecretFields(projectId, path, fields),
    () => ({
      projectId,
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
  const { userId, userEmail, projectId } = await resolveProjectContext();
  return withAudit(
    () => upsertHashicorpVaultMapping(projectId, input),
    () => ({
      projectId,
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
  const { userId, userEmail, projectId } = await resolveProjectContext();
  return withAudit(
    () => deleteHashicorpVaultMapping(projectId, input),
    () => ({
      projectId,
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
