import type { ApiEnv } from "@onecli/api";
import type { Hono } from "hono";
import { projectRoutes } from "./projects";
import { hashicorpVaultRoutes } from "./hashicorp-vault";

/**
 * Fork-owned API extensions.
 *
 * Keep route additions in this directory and register them through the
 * upstream eeRoutes seam so syncing upstream does not require editing the
 * shared API router.
 */
export const registerForkApiRoutes = (app: Hono<ApiEnv>) => {
  app.route("/projects", projectRoutes());
  app.route("/hashicorp-vault", hashicorpVaultRoutes());
};
