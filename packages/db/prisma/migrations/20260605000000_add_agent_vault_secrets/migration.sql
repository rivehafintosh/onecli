CREATE TABLE "agent_vault_secrets" (
  "agent_id" TEXT NOT NULL,
  "provider" TEXT NOT NULL,
  "hostname" TEXT NOT NULL,
  "path" TEXT NOT NULL,
  "field" TEXT NOT NULL,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "agent_vault_secrets_pkey" PRIMARY KEY ("agent_id", "provider", "hostname", "path", "field")
);

CREATE INDEX "agent_vault_secrets_agent_id_idx" ON "agent_vault_secrets"("agent_id");
CREATE INDEX "agent_vault_secrets_provider_hostname_idx" ON "agent_vault_secrets"("provider", "hostname");

ALTER TABLE "agent_vault_secrets"
  ADD CONSTRAINT "agent_vault_secrets_agent_id_fkey"
  FOREIGN KEY ("agent_id") REFERENCES "agents"("id") ON DELETE CASCADE ON UPDATE CASCADE;
