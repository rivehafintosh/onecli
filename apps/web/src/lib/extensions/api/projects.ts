import { auth, type ApiEnv } from "@onecli/api";
import { generateProjectId } from "@onecli/api/lib/ids";
import {
  ensureProjectSeeds,
  slugify,
} from "@onecli/api/services/organization-service";
import { ServiceError } from "@onecli/api/services/errors";
import { db, Prisma } from "@onecli/db";
import { Hono } from "hono";
import { z } from "zod";

const createProjectSchema = z.object({
  name: z.string().trim().min(1).max(255),
});

const updateProjectSchema = z.object({
  name: z.string().trim().min(1).max(255),
});

const projectSelect = {
  id: true,
  name: true,
  slug: true,
  createdAt: true,
} as const;

const projectWhere = (organizationId: string, userId: string) => ({
  organizationId,
  createdByUserId: userId,
});

const uniqueSlug = async (organizationId: string, name: string) => {
  const base = slugify(name) || "project";
  let candidate = base;
  for (let suffix = 2; suffix < 10_000; suffix += 1) {
    const exists = await db.project.findUnique({
      where: {
        organizationId_slug: { organizationId, slug: candidate },
      },
      select: { id: true },
    });
    if (!exists) return candidate;
    candidate = `${base}-${suffix}`;
  }
  throw new ServiceError("CONFLICT", "Could not allocate a project slug");
};

export const projectRoutes = () => {
  const app = new Hono<ApiEnv>();
  app.use("*", auth({ requireProject: false }));

  app.get("/", async (c) => {
    const current = c.get("auth");
    return c.json(
      await db.project.findMany({
        where: projectWhere(current.organizationId, current.userId),
        select: projectSelect,
        orderBy: { createdAt: "asc" },
      }),
    );
  });

  app.get("/:projectId", async (c) => {
    const current = c.get("auth");
    const project = await db.project.findFirst({
      where: {
        id: c.req.param("projectId"),
        ...projectWhere(current.organizationId, current.userId),
      },
      select: projectSelect,
    });
    if (!project) throw new ServiceError("NOT_FOUND", "Project not found");
    return c.json(project);
  });

  app.post("/", async (c) => {
    const current = c.get("auth");
    const parsed = createProjectSchema.safeParse(
      await c.req.json().catch(() => null),
    );
    if (!parsed.success) {
      return c.json(
        { error: parsed.error.issues[0]?.message ?? "Invalid request body" },
        400,
      );
    }

    const project = await db.project.create({
      data: {
        id: generateProjectId(),
        name: parsed.data.name,
        slug: await uniqueSlug(current.organizationId, parsed.data.name),
        organizationId: current.organizationId,
        createdByUserId: current.userId,
        createdByUserEmail: current.userEmail,
      },
      select: projectSelect,
    });
    await ensureProjectSeeds(project.id, current.userId, current.userEmail);
    const apiKey = await db.apiKey.findFirst({
      where: { projectId: project.id, userId: current.userId },
      select: { key: true },
    });
    return c.json({ ...project, apiKey: apiKey?.key }, 201);
  });

  app.patch("/:projectId", async (c) => {
    const current = c.get("auth");
    const parsed = updateProjectSchema.safeParse(
      await c.req.json().catch(() => null),
    );
    if (!parsed.success) {
      return c.json(
        { error: parsed.error.issues[0]?.message ?? "Invalid request body" },
        400,
      );
    }
    const existing = await db.project.findFirst({
      where: {
        id: c.req.param("projectId"),
        ...projectWhere(current.organizationId, current.userId),
      },
      select: { id: true },
    });
    if (!existing) throw new ServiceError("NOT_FOUND", "Project not found");
    return c.json(
      await db.project.update({
        where: { id: existing.id },
        data: { name: parsed.data.name },
        select: projectSelect,
      }),
    );
  });

  app.delete("/:projectId", async (c) => {
    const current = c.get("auth");
    const project = await db.project.findFirst({
      where: {
        id: c.req.param("projectId"),
        ...projectWhere(current.organizationId, current.userId),
      },
      select: { id: true },
    });
    if (!project) throw new ServiceError("NOT_FOUND", "Project not found");
    try {
      await db.project.delete({ where: { id: project.id } });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === "P2003"
      ) {
        throw new ServiceError(
          "CONFLICT",
          "Project still contains resources and cannot be deleted",
        );
      }
      throw error;
    }
    return c.body(null, 204);
  });

  return app;
};
