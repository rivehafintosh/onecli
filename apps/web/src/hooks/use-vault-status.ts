"use client";

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { GATEWAY_API_URL, IS_CLOUD } from "@/lib/env";
import { getGatewayFetchOptions } from "@/lib/gateway-auth";

export const getGatewayApiUrl = (): string => {
  if (IS_CLOUD) return GATEWAY_API_URL;
  return (
    (typeof window !== "undefined" &&
      ((window as unknown as Record<string, unknown>)
        .__GATEWAY_API_URL__ as string)) ||
    GATEWAY_API_URL
  );
};

export interface VaultStatus<T = unknown> {
  connected: boolean;
  name: string | null;
  status_data: T | null;
}

export interface BitwardenStatusData {
  fingerprint: string;
  last_error: string | null;
}

export interface OnePasswordStatusData {
  last_error: string | null;
}

export interface HashicorpVaultStatusData {
  address: string;
  mount: string;
  path_prefix: string;
  namespace: string | null;
  has_ca_cert: boolean;
  kv_version: number;
  mappings_count: number;
  token: {
    display_name: string | null;
    policies: string[];
    token_policies: string[];
    identity_policies: string[];
    ttl: number | null;
    expire_time: string | null;
    renewable: boolean | null;
    orphan: boolean | null;
    path: string | null;
  } | null;
  capabilities: Array<{
    path: string;
    capabilities: string[];
  }>;
  capabilities_error: string | null;
}

export const useVaultStatus = <T = unknown>(provider: string = "bitwarden") => {
  const [status, setStatus] = useState<VaultStatus<T> | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchStatus = useCallback(async () => {
    try {
      const { headers, credentials } = await getGatewayFetchOptions();
      const resp = await fetch(
        `${getGatewayApiUrl()}/v1/vault/${provider}/status`,
        {
          headers,
          credentials,
        },
      );
      if (resp.ok) {
        setStatus(await resp.json());
      }
    } catch {
      // Gateway unreachable
    } finally {
      setLoading(false);
    }
  }, [provider]);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  const isPaired = status?.connected || status?.status_data != null;
  const isReady = status?.connected ?? false;

  return { status, loading, isPaired, isReady, fetchStatus };
};

export const useVaultPairRequest = (
  fetchStatus: () => Promise<void>,
  provider: string,
) => {
  const [pairing, setPairing] = useState(false);

  const pairWithPayload = useCallback(
    async (payload: Record<string, unknown>): Promise<boolean> => {
      setPairing(true);
      try {
        const { headers, credentials } = await getGatewayFetchOptions();
        const resp = await fetch(
          `${getGatewayApiUrl()}/v1/vault/${provider}/pair`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json", ...headers },
            credentials,
            body: JSON.stringify(payload),
          },
        );

        if (resp.ok) {
          toast.success("Vault connected successfully");
          await fetchStatus();
          return true;
        }

        const data = await resp.json();
        toast.error(data.error ?? "Pairing failed");
        return false;
      } catch {
        toast.error("Failed to connect to vault");
        return false;
      } finally {
        setPairing(false);
      }
    },
    [fetchStatus, provider],
  );

  return { pairWithPayload, pairing };
};

export const useVaultPair = (
  fetchStatus: () => Promise<void>,
  provider: string = "bitwarden",
) => {
  const { pairWithPayload, pairing } = useVaultPairRequest(
    fetchStatus,
    provider,
  );

  const pair = useCallback(
    async (pskHex: string, fingerprintHex: string): Promise<boolean> => {
      if (pskHex.length !== 64 || fingerprintHex.length !== 64) {
        toast.error("PSK and fingerprint must each be 64 hex characters");
        return false;
      }

      return pairWithPayload({
        psk_hex: pskHex,
        fingerprint_hex: fingerprintHex,
      });
    },
    [pairWithPayload],
  );

  return { pair, pairing };
};

export const useVaultDisconnect = (
  fetchStatus: () => Promise<void>,
  provider: string = "bitwarden",
) => {
  const [disconnecting, setDisconnecting] = useState(false);

  const disconnect = useCallback(async () => {
    setDisconnecting(true);
    try {
      const { headers, credentials } = await getGatewayFetchOptions();
      const resp = await fetch(
        `${getGatewayApiUrl()}/v1/vault/${provider}/pair`,
        {
          method: "DELETE",
          headers,
          credentials,
        },
      );
      if (resp.ok) {
        toast.success("Vault disconnected");
        await fetchStatus();
      } else {
        toast.error("Failed to disconnect");
      }
    } catch {
      toast.error("Failed to disconnect");
    } finally {
      setDisconnecting(false);
    }
  }, [fetchStatus, provider]);

  return { disconnect, disconnecting };
};
