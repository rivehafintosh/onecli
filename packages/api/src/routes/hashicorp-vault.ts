import { Hono } from "hono";
import { z } from "zod";
import type { ApiEnv } from "../types";
import { authMiddleware } from "../middleware/auth";
import { invalidateGatewayCache } from "../lib/gateway-invalidate";
import {
  deleteHashicorpVaultMapping,
  getHashicorpVaultSecretMetadata,
  listHashicorpVaultMappings,
  listHashicorpVaultPath,
  upsertHashicorpVaultMapping,
  writeHashicorpVaultSecretFields,
} from "../services/hashicorp-vault-service";

const mappingSchema = z.object({
  hostname: z.string().trim().min(1),
  path: z.string(),
  field: z.string().trim().min(1),
  usernameField: z.string().optional(),
});

const writeFieldsSchema = z.object({
  path: z.string(),
  fields: z.record(z.string(), z.string()),
});

export const hashicorpVaultRoutes = () => {
  const app = new Hono<ApiEnv>();
  app.use("*", authMiddleware);

  app.get("/mappings", async (c) => {
    const auth = c.get("auth");
    return c.json(await listHashicorpVaultMappings(auth.projectId));
  });

  app.put("/mappings", async (c) => {
    const auth = c.get("auth");
    const body = await c.req.json().catch(() => null);
    const parsed = mappingSchema.safeParse(body);
    if (!parsed.success) {
      return c.json(
        { error: parsed.error.issues[0]?.message ?? "Invalid request body" },
        400,
      );
    }
    const mappings = await upsertHashicorpVaultMapping(
      auth.projectId,
      parsed.data,
    );
    invalidateGatewayCache(c.req.raw);
    return c.json(mappings);
  });

  app.delete("/mappings", async (c) => {
    const auth = c.get("auth");
    const body = await c.req.json().catch(() => null);
    const parsed = mappingSchema.safeParse(body);
    if (!parsed.success) {
      return c.json(
        { error: parsed.error.issues[0]?.message ?? "Invalid request body" },
        400,
      );
    }
    const mappings = await deleteHashicorpVaultMapping(
      auth.projectId,
      parsed.data,
    );
    invalidateGatewayCache(c.req.raw);
    return c.json(mappings);
  });

  app.get("/paths", async (c) => {
    const auth = c.get("auth");
    const path = c.req.query("path") ?? "";
    return c.json(await listHashicorpVaultPath(auth.projectId, path));
  });

  app.get("/secrets/metadata", async (c) => {
    const auth = c.get("auth");
    const path = c.req.query("path");
    if (path === undefined) return c.json({ error: "path is required" }, 400);
    return c.json(await getHashicorpVaultSecretMetadata(auth.projectId, path));
  });

  app.post("/secrets/fields", async (c) => {
    const auth = c.get("auth");
    const body = await c.req.json().catch(() => null);
    const parsed = writeFieldsSchema.safeParse(body);
    if (!parsed.success) {
      return c.json(
        { error: parsed.error.issues[0]?.message ?? "Invalid request body" },
        400,
      );
    }
    const metadata = await writeHashicorpVaultSecretFields(
      auth.projectId,
      parsed.data.path,
      parsed.data.fields,
    );
    invalidateGatewayCache(c.req.raw);
    return c.json(metadata);
  });

  return app;
};
