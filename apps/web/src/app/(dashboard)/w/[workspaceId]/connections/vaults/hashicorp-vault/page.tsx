"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { Badge } from "@onecli/ui/components/badge";
import { withWorkspacePrefix } from "@/lib/navigation";
import { HashicorpVaultSetup } from "../../_components/hashicorp-vault-setup";

export default function HashicorpVaultPage() {
  const pathname = usePathname();
  return (
    <div className="space-y-6">
      <Link
        href={withWorkspacePrefix(pathname, "/connections/vaults")}
        className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1.5 text-sm transition-colors"
      >
        <ArrowLeft className="size-4" />
        Vaults
      </Link>
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-semibold tracking-tight">
            HashiCorp Vault
          </h1>
          <Badge
            variant="secondary"
            className="px-1.5 py-0 text-[10px] font-normal"
          >
            Beta
          </Badge>
        </div>
        <p className="text-muted-foreground text-sm">
          Fetch credentials on-demand from Vault KV secrets.
        </p>
      </div>

      <HashicorpVaultSetup />
    </div>
  );
}
