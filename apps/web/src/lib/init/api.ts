import type { CreateApiAppOptions } from "@onecli/api";
import { registerForkApiRoutes } from "@/lib/extensions/api";

export const eeOverrides: CreateApiAppOptions = {
  eeRoutes: registerForkApiRoutes,
};
