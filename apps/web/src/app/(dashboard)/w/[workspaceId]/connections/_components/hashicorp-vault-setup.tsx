"use client";

import { useState } from "react";
import { toast } from "sonner";
import { AlertCircle, Database, RefreshCw, Unlink } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@onecli/ui/components/alert-dialog";
import { Badge } from "@onecli/ui/components/badge";
import { Button } from "@onecli/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@onecli/ui/components/card";
import { Input } from "@onecli/ui/components/input";
import { Label } from "@onecli/ui/components/label";
import { Skeleton } from "@onecli/ui/components/skeleton";
import {
  useVaultDisconnect,
  useVaultPairRequest,
  useVaultStatus,
  type HashicorpVaultStatusData,
} from "@/hooks/use-vault-status";
import { HashicorpVaultManager } from "./hashicorp-vault-manager";

const PROVIDER = "hashicorp-vault";

export const HashicorpVaultSetup = () => {
  const { status, loading, isPaired, isReady, fetchStatus } =
    useVaultStatus<HashicorpVaultStatusData>(PROVIDER);
  const { pairWithPayload, pairing } = useVaultPairRequest(
    fetchStatus,
    PROVIDER,
  );
  const { disconnect, disconnecting } = useVaultDisconnect(
    fetchStatus,
    PROVIDER,
  );

  const [address, setAddress] = useState("https://vault.service.consul:8200");
  const [token, setToken] = useState("");
  const [mount, setMount] = useState("kv");
  const [pathPrefix, setPathPrefix] = useState("onecli");
  const [namespace, setNamespace] = useState("");
  const [caCertPem, setCaCertPem] = useState("");
  const [kvVersion, setKvVersion] = useState("2");
  const [mappingsJson, setMappingsJson] = useState(
    '[\n  { "hostname": "api.openai.com", "path": "agents/openai", "field": "api_key" }\n]',
  );

  const canConnect = address.trim().length > 0 && token.trim().length > 0;
  const statusData = status?.status_data;
  const tokenPolicies = Array.from(
    new Set([
      ...(statusData?.token?.policies ?? []),
      ...(statusData?.token?.token_policies ?? []),
      ...(statusData?.token?.identity_policies ?? []),
    ]),
  ).sort();

  const parseMappings = () => {
    const value = mappingsJson.trim();
    if (!value) return [];
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed))
      throw new Error("Mappings must be a JSON array");
    return parsed;
  };

  const handleConnect = async () => {
    let mappings: unknown[];
    try {
      mappings = parseMappings();
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Invalid mappings JSON",
      );
      return;
    }

    const success = await pairWithPayload({
      address: address.trim(),
      token: token.trim(),
      mount: mount.trim() || "kv",
      path_prefix: pathPrefix.trim(),
      namespace: namespace.trim() || undefined,
      ca_cert_pem: caCertPem.trim() || undefined,
      kv_version: Number(kvVersion),
      mappings,
    });
    if (success) setToken("");
  };

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-44" />
          <Skeleton className="h-4 w-72" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-36 w-full" />
        </CardContent>
      </Card>
    );
  }

  if (isPaired) {
    return (
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-3">
              <CardTitle>Connection</CardTitle>
              <Badge
                variant="outline"
                className={
                  isReady
                    ? "border-brand/20 bg-brand/5 text-brand dark:border-brand/30 dark:bg-brand/10"
                    : "border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400"
                }
              >
                <span
                  className={`mr-1.5 inline-block size-1.5 rounded-full ${isReady ? "bg-brand" : "bg-red-500"}`}
                />
                {isReady ? "Connected" : "Needs attention"}
              </Badge>
            </div>
            <CardDescription>
              KV credentials are fetched by hostname when no matching local
              secret is configured.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <ReadOnlyField label="Address" value={statusData?.address} />
              <ReadOnlyField label="Mount" value={statusData?.mount} />
              <ReadOnlyField
                label="Path prefix"
                value={statusData?.path_prefix || "(root)"}
              />
              <ReadOnlyField
                label="KV version"
                value={String(statusData?.kv_version ?? 2)}
              />
              <ReadOnlyField
                label="Mappings"
                value={String(statusData?.mappings_count ?? 0)}
              />
              {statusData?.namespace ? (
                <ReadOnlyField label="Namespace" value={statusData.namespace} />
              ) : null}
              <ReadOnlyField
                label="Custom CA"
                value={statusData?.has_ca_cert ? "Configured" : "System trust"}
              />
              <ReadOnlyField
                label="Token display"
                value={statusData?.token?.display_name ?? undefined}
              />
            </div>
            <div className="space-y-3 rounded-md border p-3">
              <div className="flex items-center justify-between gap-3">
                <p className="text-sm font-medium">Token policy</p>
                {statusData?.token?.renewable != null ? (
                  <Badge variant="secondary">
                    {statusData.token.renewable ? "Renewable" : "Fixed"}
                  </Badge>
                ) : null}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {tokenPolicies.map((policy) => (
                  <Badge key={policy} variant="outline" className="font-mono">
                    {policy}
                  </Badge>
                ))}
                {tokenPolicies.length === 0 ? (
                  <p className="text-muted-foreground text-xs">
                    No token policies reported.
                  </p>
                ) : null}
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <ReadOnlyField
                  label="Auth path"
                  value={statusData?.token?.path ?? undefined}
                />
                <ReadOnlyField
                  label="TTL"
                  value={
                    statusData?.token?.ttl != null
                      ? `${statusData.token.ttl}s`
                      : undefined
                  }
                />
              </div>
            </div>
            <div className="space-y-3 rounded-md border p-3">
              <p className="text-sm font-medium">Effective capabilities</p>
              <div className="divide-border overflow-hidden rounded-md border">
                {(statusData?.capabilities ?? []).map((item) => (
                  <div
                    key={item.path}
                    className="grid gap-2 px-3 py-2 sm:grid-cols-[minmax(0,1fr)_minmax(160px,auto)]"
                  >
                    <code className="text-muted-foreground truncate text-xs">
                      {item.path}
                    </code>
                    <div className="flex flex-wrap gap-1">
                      {item.capabilities.map((capability) => (
                        <Badge
                          key={`${item.path}:${capability}`}
                          variant="secondary"
                          className="font-mono text-[10px]"
                        >
                          {capability}
                        </Badge>
                      ))}
                    </div>
                  </div>
                ))}
                {(statusData?.capabilities ?? []).length === 0 ? (
                  <p className="text-muted-foreground px-3 py-4 text-xs">
                    No capabilities reported for configured mappings.
                  </p>
                ) : null}
              </div>
              {statusData?.capabilities_error ? (
                <p className="text-destructive text-xs">
                  {statusData.capabilities_error}
                </p>
              ) : null}
            </div>
            {!isReady ? (
              <div className="bg-destructive/10 text-destructive flex items-start gap-2 rounded-md border border-red-200 p-3 text-sm dark:border-red-900">
                <AlertCircle className="mt-0.5 size-4 shrink-0" />
                <div className="grid gap-1.5">
                  <span>Vault token validation failed.</span>
                  <button
                    onClick={fetchStatus}
                    className="text-muted-foreground hover:text-foreground flex w-fit items-center gap-1 text-xs underline-offset-2 hover:underline"
                  >
                    <RefreshCw className="size-3" />
                    Refresh status
                  </button>
                </div>
              </div>
            ) : null}
          </CardContent>
        </Card>

        <HashicorpVaultManager onChanged={fetchStatus} />

        <Card>
          <CardHeader>
            <CardTitle>Disconnect</CardTitle>
            <CardDescription>
              Remove this Vault connection. Credentials will no longer be
              fetched on-demand.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="outline" className="w-fit" size="sm">
                  <Unlink className="size-3.5" />
                  Disconnect vault
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Disconnect vault?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This removes the stored Vault address and token from OneCLI.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction
                    variant="destructive"
                    onClick={disconnect}
                    disabled={disconnecting}
                  >
                    {disconnecting ? "Disconnecting..." : "Disconnect"}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Connect Vault</CardTitle>
        <CardDescription>
          Store a Vault endpoint and token for hostname-keyed KV credential
          lookup.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="grid gap-2 sm:col-span-2">
            <Label htmlFor="vault-address">Address</Label>
            <Input
              id="vault-address"
              value={address}
              onChange={(event) => setAddress(event.target.value)}
              placeholder="https://vault.example.com:8200"
            />
          </div>
          <div className="grid gap-2 sm:col-span-2">
            <Label htmlFor="vault-token">Token</Label>
            <Input
              id="vault-token"
              type="password"
              value={token}
              onChange={(event) => setToken(event.target.value)}
              placeholder="hvs..."
              className="font-mono text-sm"
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="vault-mount">KV mount</Label>
            <Input
              id="vault-mount"
              value={mount}
              onChange={(event) => setMount(event.target.value)}
              placeholder="kv"
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="vault-prefix">Path prefix</Label>
            <Input
              id="vault-prefix"
              value={pathPrefix}
              onChange={(event) => setPathPrefix(event.target.value)}
              placeholder="onecli"
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="vault-kv-version">KV version</Label>
            <Input
              id="vault-kv-version"
              value={kvVersion}
              onChange={(event) => setKvVersion(event.target.value)}
              inputMode="numeric"
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="vault-namespace">Namespace</Label>
            <Input
              id="vault-namespace"
              value={namespace}
              onChange={(event) => setNamespace(event.target.value)}
              placeholder="admin"
            />
          </div>
          <div className="grid gap-2 sm:col-span-2">
            <Label htmlFor="vault-ca-cert">CA certificate PEM</Label>
            <textarea
              id="vault-ca-cert"
              value={caCertPem}
              onChange={(event) => setCaCertPem(event.target.value)}
              className="border-input bg-transparent min-h-24 w-full rounded-md border px-3 py-2 font-mono text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
              placeholder="-----BEGIN CERTIFICATE-----"
              spellCheck={false}
            />
          </div>
          <div className="grid gap-2 sm:col-span-2">
            <Label htmlFor="vault-mappings">Credential mappings</Label>
            <textarea
              id="vault-mappings"
              value={mappingsJson}
              onChange={(event) => setMappingsJson(event.target.value)}
              className="border-input bg-transparent min-h-28 w-full rounded-md border px-3 py-2 font-mono text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
              spellCheck={false}
            />
          </div>
        </div>
        <p className="text-muted-foreground text-xs">
          Each mapping can set hostname, path, field, and optional
          username_field. Unmapped hosts fall back to path_prefix/hostname and
          token-like fields.
        </p>
        <Button
          onClick={handleConnect}
          loading={pairing}
          disabled={!canConnect || pairing}
          className="w-fit"
        >
          <Database className="size-3.5" />
          {pairing ? "Connecting..." : "Connect Vault"}
        </Button>
      </CardContent>
    </Card>
  );
};

const ReadOnlyField = ({ label, value }: { label: string; value?: string }) => (
  <div className="grid gap-1.5">
    <Label className="text-muted-foreground text-xs font-normal">{label}</Label>
    <code className="bg-muted text-muted-foreground rounded px-2 py-1.5 font-mono text-xs break-all">
      {value || "-"}
    </code>
  </div>
);
