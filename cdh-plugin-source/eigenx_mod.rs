// Copyright (c) 2026 EigenLabs
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Eigenx KMS plugin
//!
//! Thin wrapper around the `/usr/local/bin/eigenx-cdh-helper` Go binary. The
//! helper performs the actual EigenX attestation + KMS unwrap; this plugin
//! only marshals provider settings and the secret name into a JSON request on
//! the helper's stdin and returns its stdout as plaintext.

use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;

use crate::{Annotations, Error, Getter, ProviderSettings, Result};

const HELPER_BIN: &str = "/usr/local/bin/eigenx-cdh-helper";

// Hard ceiling on the helper's wall-clock time. The helper internally enforces
// a 30s AA evidence timeout, but a stalled Ethereum RPC or an operator that
// drops the /secrets connection without RST can hang it indefinitely. Without
// this cap a single misbehaving call would block CDH's plugin runtime — and
// therefore every subsequent unseal — for the lifetime of the pod. 120s is
// generous enough for the slowest legitimate flow (operator discovery + key
// share recovery) without stalling the data plane.
const HELPER_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Debug)]
pub struct EigenxKmsClient {
    provider_settings: ProviderSettings,
}

impl EigenxKmsClient {
    /// Constructed from the `provider_settings` carried in the sealed-secret
    /// envelope. The settings are stashed verbatim and forwarded to the helper
    /// on every `get_secret` call.
    pub async fn from_provider_settings(provider_settings: &ProviderSettings) -> Result<Self> {
        Ok(Self {
            provider_settings: provider_settings.clone(),
        })
    }
}

fn missing(key: &str) -> Error {
    Error::KbsClientError(format!("eigenx: missing field `{key}`"))
}

#[async_trait]
impl Getter for EigenxKmsClient {
    async fn get_secret(&self, name: &str, annotations: &Annotations) -> Result<Vec<u8>> {
        // KMS coordinates (kms_url, avs_address, operator_set_id, rpc_url) are
        // sourced from cc_init_data's [data]."eigenx.toml" by the helper itself
        // — they're SNP-bound (folded into REPORT_DATA upper 16 bytes via
        // SHA-384(cc_init_data)[:16]). The helper IGNORES any matching values
        // in provider_settings; stdin overrides would create an SSRF/operator-
        // redirect surface where a compromised CDH plugin could redirect the
        // workload to an attacker-controlled KMS without invalidating the
        // attestation. This plugin still forwards provider_settings values for
        // diagnostic / forward-compat reasons (the helper logs and drops them),
        // but new deployments should leave provider_settings empty for these
        // fields.
        //
        // Per-secret fields (app_id, ciphertext_hex) MUST come through here
        // because they're per-call: app_id = vault `name`, ciphertext_hex =
        // an annotation on the sealed envelope.
        let ps = &self.provider_settings;
        let mut request = serde_json::Map::new();
        request.insert("app_id".to_string(), Value::String(name.to_string()));
        request.insert(
            "ciphertext_hex".to_string(),
            Value::String(
                annotations
                    .get("ciphertext_hex")
                    .and_then(Value::as_str)
                    .ok_or_else(|| missing("ciphertext_hex"))?
                    .to_string(),
            ),
        );
        // Optional pass-through; absent → helper falls back to cc_init_data.
        for key in ["kms_url", "avs_address", "rpc_url"] {
            if let Some(s) = ps.get(key).and_then(Value::as_str) {
                request.insert(key.to_string(), Value::String(s.to_string()));
            }
        }
        if let Some(n) = ps.get("operator_set_id").and_then(Value::as_u64) {
            request.insert("operator_set_id".to_string(), Value::Number(n.into()));
        }
        let request = Value::Object(request);
        let payload = serde_json::to_vec(&request).map_err(|e| {
            Error::KbsClientError(format!("eigenx: serialize helper request failed: {e:?}"))
        })?;

        let mut child = Command::new(HELPER_BIN)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                Error::KbsClientError(format!("eigenx: spawn `{HELPER_BIN}` failed: {e:?}"))
            })?;

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| Error::KbsClientError("eigenx: helper stdin missing".to_string()))?;
            stdin.write_all(&payload).await.map_err(|e| {
                Error::KbsClientError(format!("eigenx: write helper stdin failed: {e:?}"))
            })?;
            stdin.shutdown().await.map_err(|e| {
                Error::KbsClientError(format!("eigenx: close helper stdin failed: {e:?}"))
            })?;
        }

        let output = match timeout(HELPER_TIMEOUT, child.wait_with_output()).await {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                return Err(Error::KbsClientError(format!(
                    "eigenx: wait for helper failed: {e:?}"
                )));
            }
            Err(_) => {
                return Err(Error::KbsClientError(format!(
                    "eigenx: helper timed out after {}s",
                    HELPER_TIMEOUT.as_secs()
                )));
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(Error::KbsClientError(format!(
                "eigenx: helper exited {}: {stderr}",
                output.status
            )));
        }

        Ok(output.stdout)
    }
}
