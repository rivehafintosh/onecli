import { z } from "zod";

export const configBodySchema = z.record(z.string(), z.string());
