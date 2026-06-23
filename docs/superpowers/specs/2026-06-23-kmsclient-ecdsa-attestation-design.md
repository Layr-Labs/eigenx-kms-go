# kmsClient CLI: ECDSA Attestation for `decrypt`

**Date:** 2026-06-23
**Status:** Approved (pending spec review)
**Scope:** `cmd/kmsClient/` only — no library changes.

## Problem

The `kms-client` CLI's `decrypt` command currently recovers an application's
private key by collecting threshold BLS partial signatures from the operators'
**unauthenticated** `/app/sign` endpoint. Operators that are configured to
require attestation (i.e. with `/app/sign` disabled, or in deployments that gate
secret access behind attestation) cannot be used from the CLI at all.

The Go library (`pkg/clients/kmsClient`) already implements ECDSA attestation
against the operators' `/secrets` endpoint via `RetrieveSecretsWithOptions`, but
the CLI does not expose it. This work surfaces that existing capability through
the `decrypt` command.

## Goal

Add an optional ECDSA-attested mode to the existing `decrypt` command. When
enabled, the CLI authenticates to operators using an ECDSA challenge-response
attestation, recovers the application private key from the attested `/secrets`
endpoint, and then decrypts the user-supplied ciphertext exactly as the
non-attested path does today.

Non-goals:
- GCP / Intel / TPM / eigenx-snp attestation methods (these require running
  inside a TEE and are not meaningful from a developer CLI).
- Changes to `encrypt` or `get-pubkey` (both remain attestation-free).
- A new top-level command. We extend `decrypt`.

## Background: how the two endpoints differ

Both endpoints ultimately return the **same** threshold BLS partial signatures
(both call `signAppIDWithVersion` server-side), and the recovered application
private key is an IBE identity derived purely from `appID`. The differences that
matter to this design:

| | `/app/sign` (today) | `/secrets` (ECDSA mode) |
|---|---|---|
| Attestation | none | ECDSA challenge-response |
| Server prerequisite | always available | operator must run `--enable-ecdsa-attestation=true` |
| On-chain dependency | none | server fetches the app's on-chain release during the request, so the app must exist on-chain |
| Transit encryption | plaintext partial sig | partial sig encrypted to a per-request RSA public key |
| Returns | partial sig only | partial sig + `encrypted_env` + `public_env` |

Security note on the ECDSA method: the server's ECDSA verification proves only
**ECDSA key ownership + challenge freshness**. It does **not** bind the ECDSA
address to the `appID`. Consequently the recovered app key is identical
regardless of which ECDSA key is presented — the attestation's only purpose from
the CLI's perspective is to satisfy operators configured to require it. This is
documented for the user; the CLI does not attempt to derive any additional
guarantee from the ECDSA key.

## CLI surface

`decrypt` gains three flags:

- `--attestation` (string, default `""`): attestation method. Accepts only
  `""` (unchanged behavior) or `ecdsa`. Any other value is a usage error.
- `--ecdsa-private-key` (string, default `""`): hex-encoded secp256k1 private
  key, used as the ECDSA attestation credential.
- `--ecdsa-private-key-file` (string, default `""`): path to a file containing a
  hex-encoded secp256k1 private key.

Flag semantics:

- `--attestation` unset → unchanged `/app/sign` flow. The two `--ecdsa-*` flags
  are ignored (no error if present).
- `--attestation ecdsa` → at least one of `--ecdsa-private-key` /
  `--ecdsa-private-key-file` is **required**. If both are provided,
  `--ecdsa-private-key` takes priority and the file is not read.
- Existing `--app-id`, `--encrypted-data`, `--threshold`, `--output` flags apply
  unchanged in both modes.

Key parsing accepts an optional `0x` prefix and tolerates surrounding
whitespace (important for `--ecdsa-private-key-file`, where editors/`echo` add a
trailing newline). Parsing uses go-ethereum's `crypto.HexToECDSA`.

### Examples

```bash
# unchanged: no attestation
kms-client --avs-address 0x.. decrypt \
  --app-id my-app --encrypted-data enc.hex

# ECDSA attestation, key passed directly
kms-client --avs-address 0x.. decrypt \
  --app-id my-app --encrypted-data enc.hex \
  --attestation ecdsa \
  --ecdsa-private-key 0xabc123...

# ECDSA attestation, key from file
kms-client --avs-address 0x.. decrypt \
  --app-id my-app --encrypted-data enc.hex \
  --attestation ecdsa \
  --ecdsa-private-key-file ./app-key.hex
```

## Implementation

All changes are in `cmd/kmsClient/main.go`.

### 1. New flags on the `decrypt` command

Add the three `cli.StringFlag`s described above to the existing `decrypt`
command's `Flags`.

### 2. ECDSA key loading helper

```go
// loadECDSAKey resolves the attestation private key from the two flags.
// --ecdsa-private-key takes priority over --ecdsa-private-key-file. At least
// one must be set. Accepts an optional 0x prefix and trims whitespace.
func loadECDSAKey(keyHex, keyFile string) (*ecdsa.PrivateKey, error)
```

- If `keyHex != ""`: parse it.
- Else if `keyFile != ""`: read the file, parse its contents.
- Else: return an error (`an ECDSA private key is required for --attestation ecdsa`).
- Parsing: `strings.TrimSpace`, strip a leading `0x`/`0X`, then
  `ethcrypto.HexToECDSA`.

This helper is pure (no I/O beyond the explicit file read) and unit-testable.

### 3. Branch in `decryptCommand`

After parsing the ciphertext (the existing hex-string-or-file logic is reused
unchanged), branch on `--attestation`:

- `""`: existing `client.Decrypt(appID, encryptedData, operators, threshold)`.
- `"ecdsa"`:
  1. `key, err := loadECDSAKey(...)`
  2. Generate an ephemeral RSA transit keypair:
     `encryption.GenerateKeyPair(2048)`.
  3. `result, err := client.RetrieveSecretsWithOptions(appID, &kmsClient.SecretsOptions{
        AttestationMethod: "ecdsa",
        ECDSAPrivateKey:   key,
        RSAPrivateKeyPEM:  priv,
        RSAPublicKeyPEM:   pub,
     })`
  4. `decryptedData, err := crypto.DecryptForApp(appID, result.AppPrivateKey, encryptedData)`
- any other value: return a usage error listing the supported methods.

The output-writing tail (`--output` via `writeSecretFile` / `prepareOutputPath`,
else stdout) is shared by both branches — extract the decrypted bytes into a
single `decryptedData []byte` and keep one output block.

Note: `RetrieveSecretsWithOptions` internally fetches operators from chain
again, so the ECDSA branch does not need the `operators` already fetched for the
non-attested path. To avoid a redundant chain round-trip, fetch operators only
in the non-attested branch (or accept the small double-fetch for code clarity —
implementer's choice, default to fetching lazily per branch).

### 4. Imports

Adds `crypto/ecdsa`, `strings` (already imported), and the project packages
`pkg/crypto`, `pkg/clients/kmsClient` (already imported), `pkg/encryption`, and
go-ethereum `crypto` (aliased `ethcrypto`).

## Error handling

- Unknown `--attestation` value → clear error naming the supported set.
- `--attestation ecdsa` with neither key flag → clear "key required" error.
- Malformed key hex → surfaced from `HexToECDSA`, wrapped with context.
- Operator-side failures (attestation disabled, app not on-chain, insufficient
  threshold) propagate from `RetrieveSecretsWithOptions` with its existing error
  messages. The CLI wraps them with `failed to retrieve secrets:` context.

## Testing

Unit tests in `cmd/kmsClient/main_test.go`:

- `loadECDSAKey`:
  - key from `--ecdsa-private-key` (with and without `0x` prefix)
  - key from `--ecdsa-private-key-file` (with trailing newline / whitespace)
  - both set → string wins (file is not even required to exist / is ignored)
  - neither set → error
  - malformed hex → error
  - file path that does not exist → error

The end-to-end attested decrypt path requires a running operator set and is
covered by existing library/integration tests for `RetrieveSecretsWithOptions`;
the CLI change is a thin wiring layer over it, so no new integration test is
added.

## Documentation

Update `cmd/kmsClient/README.md`:
- Document the `--attestation`, `--ecdsa-private-key`,
  `--ecdsa-private-key-file` flags under the Decrypt section.
- Add an "ECDSA-attested decrypt" subsection explaining the prerequisites
  (operator must enable ECDSA attestation; app must exist on-chain) and the
  security caveat (proves key ownership only).
