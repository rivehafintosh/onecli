import { auth, requireProjectId, type ApiEnv } from "@onecli/api";
import { Hono } from "hono";
import { z } from "zod";
import {
  deleteMapping,
  listMappings,
  listPath,
  metadata,
  setMapping,
  writeFields,
} from "./hashicorp-vault-service";

const mappingSchema = z.object({
  hostname: z.string().trim().min(1),
  path: z.string(),
  field: z.string().trim().min(1),
  usernameField: z.string().optional(),
});

const fieldsSchema = z.object({
  path: z.string(),
  fields: z.record(z.string(), z.string()),
});

export const hashicorpVaultRoutes = () => {
  const app = new Hono<ApiEnv>();
  app.use("*", auth());

  app.get("/mappings", async (c) =>
    c.json(await listMappings(requireProjectId(c.get("auth")))),
  );

  app.put("/mappings", async (c) => {
    const parsed = mappingSchema.safeParse(
      await c.req.json().catch(() => null),
    );
    if (!parsed.success) return c.json({ error: "Invalid request body" }, 400);
    return c.json(
      await setMapping(requireProjectId(c.get("auth")), parsed.data),
    );
  });

  app.delete("/mappings", async (c) => {
    const parsed = mappingSchema.safeParse(
      await c.req.json().catch(() => null),
    );
    if (!parsed.success) return c.json({ error: "Invalid request body" }, 400);
    return c.json(
      await deleteMapping(requireProjectId(c.get("auth")), parsed.data),
    );
  });

  app.get("/paths", async (c) =>
    c.json(
      await listPath(
        requireProjectId(c.get("auth")),
        c.req.query("path") ?? "",
      ),
    ),
  );

  app.get("/secrets/metadata", async (c) => {
    const path = c.req.query("path");
    if (path === undefined) return c.json({ error: "path is required" }, 400);
    return c.json(await metadata(requireProjectId(c.get("auth")), path));
  });

  app.post("/secrets/fields", async (c) => {
    const parsed = fieldsSchema.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json({ error: "Invalid request body" }, 400);
    return c.json(
      await writeFields(
        requireProjectId(c.get("auth")),
        parsed.data.path,
        parsed.data.fields,
      ),
    );
  });

  return app;
};
