//! HashiCorp Vault provider for per-host credential lookup.
//!
//! Vault address, token, namespace, CA certificate, KV mount, KV version, and
//! hostname-to-secret mappings are supplied through the pairing request and
//! stored encrypted with the project connection. This provider intentionally
//! does not read ambient `VAULT_*` environment variables.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::warn;

use super::{PairResult, ProviderStatus, VaultCredential, VaultProvider};
use crate::crypto::CryptoService;
use crate::db;

const PROVIDER: &str = "hashicorp-vault";
const DEFAULT_MOUNT: &str = "kv";
const DEFAULT_PATH_PREFIX: &str = "onecli";
const DEFAULT_KV_VERSION: u8 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HashicorpVaultConnectionData {
    address: String,
    token: String,
    mount: String,
    path_prefix: String,
    namespace: Option<String>,
    ca_cert_pem: Option<String>,
    kv_version: u8,
    #[serde(default)]
    mappings: Vec<CredentialMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialMapping {
    hostname: String,
    path: String,
    field: String,
    #[serde(default)]
    username_field: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PairParams {
    address: String,
    token: String,
    #[serde(default)]
    mount: Option<String>,
    #[serde(default)]
    path_prefix: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    ca_cert_pem: Option<String>,
    #[serde(default)]
    kv_version: Option<u8>,
    #[serde(default)]
    mappings: Vec<CredentialMapping>,
}

#[derive(Debug, Deserialize)]
struct VaultResponse {
    data: Option<serde_json::Value>,
}

pub(crate) struct HashicorpVaultProvider {
    pool: PgPool,
    crypto: Arc<CryptoService>,
}

impl HashicorpVaultProvider {
    pub(crate) fn new(pool: PgPool, crypto: Arc<CryptoService>) -> Self {
        Self { pool, crypto }
    }

    async fn load_connection(
        &self,
        project_id: &str,
    ) -> Result<Option<HashicorpVaultConnectionData>> {
        let row = match db::find_vault_connection(&self.pool, project_id, PROVIDER).await? {
            Some(row) => row,
            None => return Ok(None),
        };
        let Some(value) = row.connection_data else {
            return Ok(None);
        };
        decrypt_connection_data(&self.crypto, &value)
            .await
            .map(Some)
    }

    async fn validate(&self, data: &HashicorpVaultConnectionData) -> Result<Option<String>> {
        let url = format!(
            "{}/v1/auth/token/lookup-self",
            data.address.trim_end_matches('/')
        );
        let client = client_for(data)?;
        let resp = client
            .get(url)
            .headers(headers(data)?)
            .send()
            .await
            .context("calling Vault token lookup-self")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::FORBIDDEN && token_lookup_forbidden_is_usable(&body) {
                warn!(
                    "HashiCorp Vault token cannot call lookup-self; accepting token for KV reads"
                );
                return Ok(None);
            }
            return Err(anyhow!("Vault token validation failed: {status} {body}"));
        }

        let value: serde_json::Value = resp.json().await.context("parsing Vault token lookup")?;
        Ok(value
            .get("data")
            .and_then(|d| d.get("display_name"))
            .and_then(|v| v.as_str())
            .map(str::to_string))
    }

    async fn read_secret(
        &self,
        data: &HashicorpVaultConnectionData,
        hostname: &str,
    ) -> Result<Option<VaultCredential>> {
        let client = client_for(data)?;
        let headers = headers(data)?;

        for lookup in candidate_lookups(data, hostname) {
            let url = format!(
                "{}/v1/{}",
                data.address.trim_end_matches('/'),
                lookup.api_path
            );
            let resp = client.get(url).headers(headers.clone()).send().await;
            let resp = match resp {
                Ok(resp) => resp,
                Err(e) => {
                    warn!(host = %hostname, error = %e, "hashicorp vault request failed");
                    continue;
                }
            };

            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                continue;
            }
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                warn!(
                    host = %hostname,
                    path = %lookup.api_path,
                    status = %status,
                    body = %body,
                    "hashicorp vault secret lookup failed"
                );
                continue;
            }

            let body: VaultResponse = match resp.json().await {
                Ok(body) => body,
                Err(e) => {
                    warn!(host = %hostname, error = %e, "hashicorp vault response parse failed");
                    continue;
                }
            };

            let secret = match data.kv_version {
                2 => body.data.and_then(|d| d.get("data").cloned()),
                _ => body.data,
            };
            if let Some(secret) = secret.and_then(|v| v.as_object().cloned()) {
                if let Some(credential) = credential_from_map(
                    &secret,
                    lookup.field.as_deref(),
                    lookup.username_field.as_deref(),
                ) {
                    return Ok(Some(credential));
                }
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl VaultProvider for HashicorpVaultProvider {
    fn provider_name(&self) -> &'static str {
        PROVIDER
    }

    async fn pair(&self, project_id: &str, params: &serde_json::Value) -> Result<PairResult> {
        let params: PairParams = serde_json::from_value(params.clone())
            .context("invalid HashiCorp Vault connection params")?;
        let data = HashicorpVaultConnectionData {
            address: normalize_address(&params.address)?,
            token: require_non_empty(params.token, "token")?,
            mount: normalize_segment(params.mount.as_deref().unwrap_or(DEFAULT_MOUNT), "mount")?,
            path_prefix: normalize_prefix(
                params.path_prefix.as_deref().unwrap_or(DEFAULT_PATH_PREFIX),
            ),
            namespace: params.namespace.and_then(|s| non_empty_trimmed(&s)),
            ca_cert_pem: params.ca_cert_pem.and_then(|s| non_empty_trimmed(&s)),
            kv_version: params.kv_version.unwrap_or(DEFAULT_KV_VERSION),
            mappings: normalize_mappings(params.mappings)?,
        };

        if data.kv_version != 1 && data.kv_version != 2 {
            return Err(anyhow!("kv_version must be 1 or 2"));
        }

        let display_name = self.validate(&data).await?;
        let encrypted = encrypt_connection_data(&self.crypto, &data).await?;
        db::upsert_vault_connection(
            &self.pool,
            project_id,
            PROVIDER,
            "connected",
            Some(&encrypted),
        )
        .await?;

        Ok(PairResult { display_name })
    }

    async fn request_credential(
        &self,
        project_id: &str,
        hostname: &str,
    ) -> Option<VaultCredential> {
        let data = match self.load_connection(project_id).await {
            Ok(Some(data)) => data,
            Ok(None) => return None,
            Err(e) => {
                warn!(error = %e, "failed to load HashiCorp Vault connection");
                return None;
            }
        };

        match self.read_secret(&data, hostname).await {
            Ok(credential) => credential,
            Err(e) => {
                warn!(host = %hostname, error = %e, "HashiCorp Vault credential lookup failed");
                None
            }
        }
    }

    async fn status(&self, project_id: &str) -> ProviderStatus {
        let data = match self.load_connection(project_id).await {
            Ok(Some(data)) => data,
            _ => {
                return ProviderStatus {
                    connected: false,
                    name: None,
                    status_data: None,
                }
            }
        };

        let validation = self.validate(&data).await;
        ProviderStatus {
            connected: validation.is_ok(),
            name: validation.ok().flatten(),
            status_data: Some(serde_json::json!({
                "address": data.address,
                "mount": data.mount,
                "path_prefix": data.path_prefix,
                "namespace": data.namespace,
                "has_ca_cert": data.ca_cert_pem.is_some(),
                "kv_version": data.kv_version,
                "mappings_count": data.mappings.len(),
            })),
        }
    }

    async fn disconnect(&self, _project_id: &str) -> Result<()> {
        Ok(())
    }
}

fn headers(data: &HashicorpVaultConnectionData) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-vault-token",
        HeaderValue::from_str(&data.token).context("invalid Vault token header")?,
    );
    if let Some(namespace) = &data.namespace {
        headers.insert(
            "x-vault-namespace",
            HeaderValue::from_str(namespace).context("invalid Vault namespace header")?,
        );
    }
    Ok(headers)
}

fn client_for(data: &HashicorpVaultConnectionData) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
    if let Some(ca_cert_pem) = &data.ca_cert_pem {
        let cert = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())
            .context("invalid Vault CA certificate PEM")?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build()
        .context("building HashiCorp Vault HTTP client")
}

struct SecretLookup {
    api_path: String,
    field: Option<String>,
    username_field: Option<String>,
}

fn candidate_lookups(data: &HashicorpVaultConnectionData, hostname: &str) -> Vec<SecretLookup> {
    let host = hostname.trim().trim_matches('/');
    let mut lookups: Vec<SecretLookup> = data
        .mappings
        .iter()
        .filter(|mapping| mapping.hostname.trim().eq_ignore_ascii_case(host))
        .map(|mapping| SecretLookup {
            api_path: api_path(data, &mapping.path),
            field: Some(mapping.field.clone()),
            username_field: mapping.username_field.clone(),
        })
        .collect();

    let fallback_path = if data.path_prefix.is_empty() {
        host.to_string()
    } else {
        format!("{}/{}", data.path_prefix, host)
    };
    lookups.push(SecretLookup {
        api_path: api_path(data, &fallback_path),
        field: None,
        username_field: None,
    });
    lookups
}

fn api_path(data: &HashicorpVaultConnectionData, logical_path: &str) -> String {
    let logical_path = logical_path.trim().trim_matches('/');
    match data.kv_version {
        2 => format!("{}/data/{}", data.mount, logical_path),
        _ => format!("{}/{}", data.mount, logical_path),
    }
}

fn credential_from_map(
    map: &serde_json::Map<String, serde_json::Value>,
    field: Option<&str>,
    username_field: Option<&str>,
) -> Option<VaultCredential> {
    let username = username_field
        .and_then(|name| string_field(map, &[name]))
        .or_else(|| string_field(map, &["username", "user", "login"]));
    let password = field
        .and_then(|name| string_field(map, &[name]))
        .or_else(|| string_field(map, &["password", "token", "api_key", "apikey", "value"]))?;
    Some(VaultCredential {
        username,
        password: Some(password),
    })
}

fn string_field(
    map: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
) -> Option<String> {
    names.iter().find_map(|name| {
        map.get(*name)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    })
}

fn token_lookup_forbidden_is_usable(body: &str) -> bool {
    let body = body.to_ascii_lowercase();
    body.contains("permission denied") && !body.contains("invalid token")
}

fn normalize_mappings(mappings: Vec<CredentialMapping>) -> Result<Vec<CredentialMapping>> {
    mappings
        .into_iter()
        .filter(|mapping| {
            !mapping.hostname.trim().is_empty()
                || !mapping.path.trim().is_empty()
                || !mapping.field.trim().is_empty()
        })
        .map(|mapping| {
            Ok(CredentialMapping {
                hostname: require_non_empty(mapping.hostname, "mapping hostname")?,
                path: normalize_segment(&mapping.path, "mapping path")?,
                field: require_non_empty(mapping.field, "mapping field")?,
                username_field: mapping.username_field.and_then(|s| non_empty_trimmed(&s)),
            })
        })
        .collect()
}

fn normalize_address(value: &str) -> Result<String> {
    let value = require_non_empty(value.to_string(), "address")?;
    if !value.starts_with("http://") && !value.starts_with("https://") {
        return Err(anyhow!("address must start with http:// or https://"));
    }
    Ok(value.trim_end_matches('/').to_string())
}

fn normalize_segment(value: &str, name: &str) -> Result<String> {
    let value = require_non_empty(value.to_string(), name)?;
    let value = value.trim_matches('/').to_string();
    if value.contains("..") {
        return Err(anyhow!("{name} cannot contain '..'"));
    }
    Ok(value)
}

fn normalize_prefix(value: &str) -> String {
    value.trim().trim_matches('/').to_string()
}

fn require_non_empty(value: String, name: &str) -> Result<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(anyhow!("{name} is required"));
    }
    Ok(value)
}

fn non_empty_trimmed(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

async fn encrypt_connection_data(
    crypto: &CryptoService,
    cd: &HashicorpVaultConnectionData,
) -> Result<serde_json::Value> {
    let json_str =
        serde_json::to_string(cd).context("serializing HashiCorp Vault connection data")?;
    let encrypted = crypto
        .encrypt(&json_str)
        .await
        .context("encrypting HashiCorp Vault connection data")?;
    Ok(serde_json::json!({ "encrypted": encrypted }))
}

async fn decrypt_connection_data(
    crypto: &CryptoService,
    value: &serde_json::Value,
) -> Result<HashicorpVaultConnectionData> {
    if let Some(encrypted_str) = value.get("encrypted").and_then(|v| v.as_str()) {
        let json_str = crypto
            .decrypt(encrypted_str)
            .await
            .context("decrypting HashiCorp Vault connection data")?;
        serde_json::from_str(&json_str).context("deserializing HashiCorp Vault connection data")
    } else {
        serde_json::from_value(value.clone())
            .context("deserializing legacy HashiCorp Vault connection data")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_paths_for_kv_v2() {
        let data = HashicorpVaultConnectionData {
            address: "https://vault.example.com".into(),
            token: "token".into(),
            mount: "secret".into(),
            path_prefix: "onecli".into(),
            namespace: None,
            ca_cert_pem: None,
            kv_version: 2,
            mappings: vec![],
        };
        let paths: Vec<String> = candidate_lookups(&data, "api.openai.com")
            .into_iter()
            .map(|lookup| lookup.api_path)
            .collect();
        assert_eq!(paths, vec!["secret/data/onecli/api.openai.com"]);
    }

    #[test]
    fn credential_accepts_token_field() {
        let mut map = serde_json::Map::new();
        map.insert("token".into(), serde_json::Value::String("sk-test".into()));
        let credential = credential_from_map(&map, None, None).expect("credential");
        assert_eq!(credential.password.as_deref(), Some("sk-test"));
    }

    #[test]
    fn lookup_self_permission_denied_is_usable() {
        assert!(token_lookup_forbidden_is_usable(
            r#"{"errors":["permission denied"]}"#
        ));
    }

    #[test]
    fn lookup_self_invalid_token_is_rejected() {
        assert!(!token_lookup_forbidden_is_usable(
            r#"{"errors":["permission denied","invalid token"]}"#
        ));
    }
}

#[cfg(test)]
mod mapping_tests {
    use super::*;

    #[test]
    fn mapping_overrides_path_and_field() {
        let data = HashicorpVaultConnectionData {
            address: "https://vault.example.com".into(),
            token: "token".into(),
            mount: "secret".into(),
            path_prefix: "onecli".into(),
            namespace: None,
            ca_cert_pem: None,
            kv_version: 2,
            mappings: vec![CredentialMapping {
                hostname: "api.anthropic.com".into(),
                path: "agents/anthropic".into(),
                field: "claude_key".into(),
                username_field: None,
            }],
        };
        let lookups = candidate_lookups(&data, "api.anthropic.com");
        assert_eq!(lookups[0].api_path, "secret/data/agents/anthropic");
        assert_eq!(lookups[0].field.as_deref(), Some("claude_key"));
        assert_eq!(lookups[1].api_path, "secret/data/onecli/api.anthropic.com");
    }
}
