"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { Badge } from "@onecli/ui/components/badge";
import { withProjectPrefix } from "@/lib/navigation";
import { HashicorpVaultSetup } from "../../_components/hashicorp-vault-setup";

export default function HashicorpVaultPage() {
  const pathname = usePathname();
  return (
    <div className="space-y-6">
      <Link
        href={withProjectPrefix(pathname, "/connections/vaults")}
        className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
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
            className="text-[10px] font-normal px-1.5 py-0"
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
