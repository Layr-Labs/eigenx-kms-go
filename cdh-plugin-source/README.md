# CDH eigenx plugin (staging)

Source for the `eigenx` plugin in `confidential-data-hub` (CDH). These files
are staged here so `podvm-build.sh` can drop them into the upstream
`guest-components` checkout right next to the existing `cc_kbc.rs` patch.

Pinned upstream SHA: `0c1490f1fbecff87cd1c9c1126e6b89afb23572d`.

## Files

- `eigenx_mod.rs` — full source for
  `confidential-data-hub/kms/src/plugins/eigenx/mod.rs`. Implements `Getter`
  by shelling out to `/usr/local/bin/eigenx-cdh-helper` over stdio. No crypto
  or HTTP in Rust; the Go helper does it all.
- `plugins_mod_rs.patch` — unified diff against
  `confidential-data-hub/kms/src/plugins/mod.rs` adding `pub mod eigenx;`,
  the `Eigenx` variant on `VaultProvider`, and the dispatch arm in
  `new_getter`. Unconditional (no Cargo feature flag).

## Wire contract (helper stdin)

```json
{
  "app_id": "<vault-name from sealed envelope>",
  "ciphertext_hex": "<from annotations>"
}
```

The plugin still forwards `kms_url` / `avs_address` / `operator_set_id` /
`rpc_url` from `provider_settings` for forward-compat / diagnostics, but
the **helper ignores them**. Those fields are sourced from
`cc_init_data`'s `[data]."eigenx.toml"` — SNP-bound: an attacker tampering
with cc_init_data invalidates the SHA-384 digest folded into the AMD-
signed REPORT_DATA. Letting the CDH plugin override them on stdin would
create an SSRF/operator-redirect surface where a compromised plugin could
redirect the workload to an attacker-controlled KMS without invalidating
the attestation. See `cmd/kmsCDHHelper/main.go::applyInitdataKMSConfig`
for the full rationale.

New deployments should leave `provider_settings` empty for those fields.

## How podvm-build.sh consumes them

In step 7, after the existing `cc_kbc.rs` heredoc and before `cargo build`:

```bash
mkdir -p confidential-data-hub/kms/src/plugins/eigenx
cat > confidential-data-hub/kms/src/plugins/eigenx/mod.rs <<'EOF'
... contents of eigenx_mod.rs ...
EOF
patch -p1 < /path/to/plugins_mod_rs.patch
```

No new crates needed: `serde_json`, `tokio` (with `process` + `io-util`),
`async-trait`, and `thiserror` are already workspace deps of the `kms`
crate.
