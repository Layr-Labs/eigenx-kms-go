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

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::{Annotations, Error, Getter, ProviderSettings, Result};

const HELPER_BIN: &str = "/usr/local/bin/eigenx-cdh-helper";

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
        let ps = &self.provider_settings;
        let request = json!({
            "kms_url": ps.get("kms_url").and_then(Value::as_str).ok_or_else(|| missing("kms_url"))?,
            "avs_address": ps.get("avs_address").and_then(Value::as_str).ok_or_else(|| missing("avs_address"))?,
            "operator_set_id": ps.get("operator_set_id").and_then(Value::as_i64).ok_or_else(|| missing("operator_set_id"))?,
            "rpc_url": ps.get("rpc_url").and_then(Value::as_str).ok_or_else(|| missing("rpc_url"))?,
            "app_id": name,
            "ciphertext_hex": annotations.get("ciphertext_hex").and_then(Value::as_str).ok_or_else(|| missing("ciphertext_hex"))?,
        });
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

        let output = child.wait_with_output().await.map_err(|e| {
            Error::KbsClientError(format!("eigenx: wait for helper failed: {e:?}"))
        })?;

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
