# kmsClient ECDSA Attestation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the `kms-client decrypt` command optionally authenticate to operators with ECDSA challenge-response attestation, recovering the app private key from the attested `/secrets` endpoint before decrypting the user's ciphertext.

**Architecture:** A thin CLI wiring layer over the existing library method `kmsClient.Client.RetrieveSecretsWithOptions`. `decrypt` gains `--attestation`, `--ecdsa-private-key`, and `--ecdsa-private-key-file` flags. When `--attestation ecdsa` is set, the CLI loads the ECDSA key, generates an ephemeral RSA transit keypair, calls `RetrieveSecretsWithOptions` to recover `AppPrivateKey`, then decrypts the supplied ciphertext via `crypto.DecryptForApp`. When unset, behavior is identical to today (`/app/sign`).

**Tech Stack:** Go, `urfave/cli/v2`, go-ethereum `crypto` (secp256k1 key parsing), project packages `pkg/clients/kmsClient`, `pkg/crypto`, `pkg/encryption`.

## Global Constraints

- All changes live in `cmd/kmsClient/` plus its README. No library (`pkg/`) changes.
- Supported `--attestation` values are exactly `""` (no attestation, legacy `/app/sign`) and `ecdsa`. Any other value is a usage error.
- `--ecdsa-private-key` (hex string) takes priority over `--ecdsa-private-key-file` (path). When `--attestation ecdsa`, at least one must be set.
- ECDSA key hex tolerates an optional `0x`/`0X` prefix and surrounding whitespace; parsed with go-ethereum `crypto.HexToECDSA` (which itself does NOT accept a `0x` prefix — the prefix must be stripped first).
- Run tests via `./scripts/goTest.sh` (NOT `go test` directly). The script spins up web3signer docker containers, then forwards its arguments to `go test -timeout 10m`.
- Commits must NOT include any `Co-Authored-By` trailer.
- go-ethereum's `crypto` package is imported aliased as `ethcrypto`; the project's `pkg/crypto` is imported unaliased as `crypto`.

---

## File Structure

- `cmd/kmsClient/main.go` — Modify: add three flags to the `decrypt` command, add `loadECDSAKey`, `parseEncryptedInput`, `decryptWithoutAttestation`, and `decryptWithECDSAAttestation` helpers, and rewrite `decryptCommand` to branch on `--attestation` with a shared output tail.
- `cmd/kmsClient/main_test.go` — Modify: add `TestLoadECDSAKey` table of subtests.
- `cmd/kmsClient/README.md` — Modify: document the new flags and the ECDSA-attested decrypt mode, including prerequisites and the security caveat.

---

### Task 1: ECDSA key-loading helper

**Files:**
- Modify: `cmd/kmsClient/main.go` (add `loadECDSAKey` and its imports)
- Test: `cmd/kmsClient/main_test.go` (add `TestLoadECDSAKey`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `func loadECDSAKey(keyHex, keyFile string) (*ecdsa.PrivateKey, error)` — resolves the ECDSA attestation key from the two flag values; `keyHex` takes priority over `keyFile`; errors if neither is set or the hex is invalid.

- [ ] **Step 1: Write the failing test**

Add to `cmd/kmsClient/main_test.go`. Add these imports to the file's import block: `"encoding/hex"`, and `ethcrypto "github.com/ethereum/go-ethereum/crypto"` (keep the existing `os`, `path/filepath`, `strings`, `testing`, and `require` imports).

```go
func TestLoadECDSAKey(t *testing.T) {
	// A freshly generated key gives us a known-good hex encoding and address
	// to round-trip through loadECDSAKey.
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	keyHex := hex.EncodeToString(ethcrypto.FromECDSA(key))
	wantAddr := ethcrypto.PubkeyToAddress(key.PublicKey)

	t.Run("loads key from hex string", func(t *testing.T) {
		got, err := loadECDSAKey(keyHex, "")
		require.NoError(t, err)
		require.Equal(t, wantAddr, ethcrypto.PubkeyToAddress(got.PublicKey))
	})

	t.Run("tolerates 0x prefix and surrounding whitespace", func(t *testing.T) {
		got, err := loadECDSAKey("  0x"+keyHex+"\n", "")
		require.NoError(t, err)
		require.Equal(t, wantAddr, ethcrypto.PubkeyToAddress(got.PublicKey))
	})

	t.Run("loads key from file with trailing newline", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key.hex")
		require.NoError(t, os.WriteFile(path, []byte(keyHex+"\n"), 0600))

		got, err := loadECDSAKey("", path)
		require.NoError(t, err)
		require.Equal(t, wantAddr, ethcrypto.PubkeyToAddress(got.PublicKey))
	})

	t.Run("hex string takes priority over file", func(t *testing.T) {
		// File holds a DIFFERENT valid key; the string value must win.
		other, err := ethcrypto.GenerateKey()
		require.NoError(t, err)
		path := filepath.Join(t.TempDir(), "other.hex")
		require.NoError(t, os.WriteFile(path, []byte(hex.EncodeToString(ethcrypto.FromECDSA(other))), 0600))

		got, err := loadECDSAKey(keyHex, path)
		require.NoError(t, err)
		require.Equal(t, wantAddr, ethcrypto.PubkeyToAddress(got.PublicKey),
			"hex string key must take priority over the file")
	})

	t.Run("errors when neither flag is set", func(t *testing.T) {
		_, err := loadECDSAKey("", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "required")
	})

	t.Run("errors on malformed hex", func(t *testing.T) {
		_, err := loadECDSAKey("not-valid-hex-zzzz", "")
		require.Error(t, err)
	})

	t.Run("errors when file does not exist", func(t *testing.T) {
		_, err := loadECDSAKey("", filepath.Join(t.TempDir(), "does-not-exist.hex"))
		require.Error(t, err)
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/goTest.sh ./cmd/kmsClient/ -run TestLoadECDSAKey -v`
Expected: compile failure — `undefined: loadECDSAKey` (and possibly `ethcrypto` imported and not used until the helper exists; if the package fails to compile that is the expected red state).

- [ ] **Step 3: Add imports and implement `loadECDSAKey`**

In `cmd/kmsClient/main.go`, update the import block to add `"crypto/ecdsa"` (stdlib group) and `ethcrypto "github.com/ethereum/go-ethereum/crypto"` (third-party group). The block becomes:

```go
import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/urfave/cli/v2"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
)
```

Add the helper near the other helpers at the end of the file:

```go
// loadECDSAKey resolves the ECDSA attestation private key from the two decrypt
// flags. keyHex (--ecdsa-private-key) takes priority over keyFile
// (--ecdsa-private-key-file); at least one must be non-empty. The key is a
// hex-encoded secp256k1 private key. An optional 0x/0X prefix and surrounding
// whitespace are tolerated — a trailing newline is common when the key is read
// from a file.
func loadECDSAKey(keyHex, keyFile string) (*ecdsa.PrivateKey, error) {
	var raw string
	switch {
	case keyHex != "":
		raw = keyHex
	case keyFile != "":
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read ECDSA private key file: %w", err)
		}
		raw = string(b)
	default:
		return nil, fmt.Errorf("an ECDSA private key is required for --attestation ecdsa: set --ecdsa-private-key or --ecdsa-private-key-file")
	}

	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "0x")
	raw = strings.TrimPrefix(raw, "0X")

	key, err := ethcrypto.HexToECDSA(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid ECDSA private key: %w", err)
	}
	return key, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./scripts/goTest.sh ./cmd/kmsClient/ -run TestLoadECDSAKey -v`
Expected: PASS — all eight subtests green.

- [ ] **Step 5: Commit**

```bash
git add cmd/kmsClient/main.go cmd/kmsClient/main_test.go
git commit -m "feat(kmsClient): add ECDSA attestation key-loading helper"
```

---

### Task 2: Wire ECDSA attestation into `decrypt`

**Files:**
- Modify: `cmd/kmsClient/main.go` (add flags to `decrypt`, add `parseEncryptedInput`, `decryptWithoutAttestation`, `decryptWithECDSAAttestation`, rewrite `decryptCommand`)

**Interfaces:**
- Consumes: `loadECDSAKey(keyHex, keyFile string) (*ecdsa.PrivateKey, error)` from Task 1.
- Produces: a `decrypt` command exposing `--attestation`, `--ecdsa-private-key`, `--ecdsa-private-key-file`; internal helpers `parseEncryptedInput(input string) ([]byte, error)`, `decryptWithoutAttestation(client *kmsClient.Client, appID string, encryptedData []byte, threshold int) ([]byte, error)`, and `decryptWithECDSAAttestation(c *cli.Context, client *kmsClient.Client, appID string, encryptedData []byte) ([]byte, error)`.

- [ ] **Step 1: Add the three flags to the `decrypt` command**

In `cmd/kmsClient/main.go`, in the `decrypt` command's `Flags` slice (currently `app-id`, `encrypted-data`, `threshold`, `output`), append:

```go
&cli.StringFlag{
	Name:  "attestation",
	Usage: "Attestation method. Empty (default) uses the unauthenticated /app/sign endpoint; \"ecdsa\" uses ECDSA challenge-response attestation against /secrets.",
	Value: "",
},
&cli.StringFlag{
	Name:  "ecdsa-private-key",
	Usage: "Hex-encoded secp256k1 private key for ECDSA attestation (takes priority over --ecdsa-private-key-file). Required when --attestation ecdsa.",
	Value: "",
},
&cli.StringFlag{
	Name:  "ecdsa-private-key-file",
	Usage: "Path to a file holding a hex-encoded secp256k1 private key for ECDSA attestation. Used when --ecdsa-private-key is not set.",
	Value: "",
},
```

- [ ] **Step 2: Add the remaining imports**

Update the import block to add the project `crypto` and `encryption` packages (third-party/project group). The block becomes:

```go
import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Layr-Labs/chain-indexer/pkg/clients/ethereum"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/urfave/cli/v2"

	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/kmsClient"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller/caller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/encryption"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/logger"
)
```

- [ ] **Step 3: Replace `decryptCommand` and add the three helpers**

Replace the entire existing `decryptCommand` function with the version below, and add the three helpers immediately after it. (The ciphertext-parsing logic that used to be inline now lives in `parseEncryptedInput`; the output-writing tail is shared by both decrypt paths.)

```go
// decryptCommand handles the decrypt subcommand
func decryptCommand(c *cli.Context) error {
	appID := c.String("app-id")
	encryptedInput := c.String("encrypted-data")
	threshold := c.Int("threshold")
	outputFile := c.String("output")
	attestationMethod := c.String("attestation")

	// Validate the attestation method up front so a typo fails fast before any
	// file or network work. Empty selects the legacy no-attestation /app/sign
	// flow; "ecdsa" is the only attested method meaningful from a CLI
	// (GCP/Intel/SNP require running inside a TEE).
	switch attestationMethod {
	case "", "ecdsa":
		// supported
	default:
		return fmt.Errorf("unsupported --attestation %q: supported values are \"\" (none) and \"ecdsa\"", attestationMethod)
	}

	fmt.Printf("🔓 Decrypting data for app: %s\n", appID)

	// Create KMS client
	client, err := createClient(c)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Parse encrypted data (hex string or file) up front — independent of the
	// attestation path and cheap to fail on.
	encryptedData, err := parseEncryptedInput(encryptedInput)
	if err != nil {
		return err
	}

	// Recover the plaintext via the selected path.
	var decryptedData []byte
	if attestationMethod == "ecdsa" {
		decryptedData, err = decryptWithECDSAAttestation(c, client, appID, encryptedData)
	} else {
		decryptedData, err = decryptWithoutAttestation(client, appID, encryptedData, threshold)
	}
	if err != nil {
		return err
	}

	// Output result (shared by both paths)
	if outputFile != "" {
		cleanPath, pathErr := prepareOutputPath(outputFile)
		if pathErr != nil {
			return fmt.Errorf("invalid --output path: %w", pathErr)
		}
		if err := writeSecretFile(cleanPath, decryptedData); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
		fmt.Printf("✅ Decrypted data written to: %s\n", cleanPath)
		fmt.Fprintf(os.Stderr, "note: output file written with mode 0600 (owner read/write only); verify perms if you chmod it wider\n")
	} else {
		fmt.Printf("✅ Decrypted data: %s\n", string(decryptedData))
	}

	return nil
}

// parseEncryptedInput resolves the --encrypted-data value, which may be either
// a path to a file containing hex or a hex string directly. It accepts the
// 0x-prefixed output that `encrypt --output` writes; TrimSpace handles trailing
// newlines from editors or `echo`.
func parseEncryptedInput(input string) ([]byte, error) {
	if _, statErr := os.Stat(input); statErr == nil {
		fileData, readErr := os.ReadFile(input)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read encrypted data file: %w", readErr)
		}
		data, decodeErr := hexutil.Decode(strings.TrimSpace(string(fileData)))
		if decodeErr != nil {
			return nil, fmt.Errorf("failed to decode hex data from file: %w", decodeErr)
		}
		return data, nil
	}

	fmt.Printf("Using encrypted input %s\n", input)
	data, decodeErr := hexutil.Decode(strings.TrimSpace(input))
	if decodeErr != nil {
		return nil, fmt.Errorf("failed to decode hex data: %w", decodeErr)
	}
	return data, nil
}

// decryptWithoutAttestation recovers the plaintext via the unauthenticated
// /app/sign endpoint — the CLI's original behavior.
func decryptWithoutAttestation(client *kmsClient.Client, appID string, encryptedData []byte, threshold int) ([]byte, error) {
	operators, err := client.GetOperators()
	if err != nil {
		return nil, fmt.Errorf("failed to get operators: %w", err)
	}

	decryptedData, err := client.Decrypt(appID, encryptedData, operators, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}
	return decryptedData, nil
}

// decryptWithECDSAAttestation recovers the application private key from the
// attested /secrets endpoint using ECDSA challenge-response attestation, then
// decrypts the user-supplied ciphertext with it. Unlike the no-attestation
// path, this requires the operators to have ECDSA attestation enabled and the
// app to exist on-chain (the operator fetches the app's release while serving
// the request).
func decryptWithECDSAAttestation(c *cli.Context, client *kmsClient.Client, appID string, encryptedData []byte) ([]byte, error) {
	key, err := loadECDSAKey(c.String("ecdsa-private-key"), c.String("ecdsa-private-key-file"))
	if err != nil {
		return nil, err
	}

	// The /secrets endpoint encrypts each partial signature to a per-request
	// RSA public key. This keypair is transport-level only and never leaves
	// this process, so we generate an ephemeral one per invocation.
	rsaPrivPEM, rsaPubPEM, err := encryption.GenerateKeyPair(2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral RSA key pair: %w", err)
	}

	result, err := client.RetrieveSecretsWithOptions(appID, &kmsClient.SecretsOptions{
		AttestationMethod: "ecdsa",
		ECDSAPrivateKey:   key,
		RSAPrivateKeyPEM:  rsaPrivPEM,
		RSAPublicKeyPEM:   rsaPubPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve secrets: %w", err)
	}

	decryptedData, err := crypto.DecryptForApp(appID, result.AppPrivateKey, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}
	return decryptedData, nil
}
```

- [ ] **Step 4: Build to verify it compiles**

Run: `go build ./cmd/kmsClient/`
Expected: no output, exit 0. (Confirms imports resolve and no unused-import errors — `crypto`, `encryption`, `ecdsa`, `ethcrypto` are all now used.)

- [ ] **Step 5: Verify the flags are wired by inspecting `decrypt --help`**

Run:
```bash
go build -o /tmp/kms-client ./cmd/kmsClient/ && /tmp/kms-client decrypt --help
```
Expected: the help output lists `--attestation`, `--ecdsa-private-key`, and `--ecdsa-private-key-file` alongside the existing `--app-id`, `--encrypted-data`, `--threshold`, `--output`.

- [ ] **Step 6: Run the package test suite to confirm no regression**

Run: `./scripts/goTest.sh ./cmd/kmsClient/ -v`
Expected: PASS — `TestLoadECDSAKey`, `TestWriteSecretFile`, and `TestPrepareOutputPath` all green.

- [ ] **Step 7: Commit**

```bash
git add cmd/kmsClient/main.go
git commit -m "feat(kmsClient): support ECDSA attestation in decrypt command"
```

---

### Task 3: Document the ECDSA-attested decrypt mode

**Files:**
- Modify: `cmd/kmsClient/README.md`

**Interfaces:**
- Consumes: the flags and behavior added in Task 2.
- Produces: user-facing docs (no code interface).

- [ ] **Step 1: Add the flag docs and ECDSA subsection under "Decrypt Data"**

In `cmd/kmsClient/README.md`, immediately after the existing "Decrypt Data" code block (the one ending with the `--threshold 2` example, before the `## How It Works` heading), insert:

````markdown
#### Decrypt Data with ECDSA Attestation

Some operator deployments require attestation before serving an application's
key material. The `decrypt` command can authenticate with an ECDSA
challenge-response attestation against the operators' `/secrets` endpoint:

```bash
# ECDSA key passed directly (hex, 0x prefix optional)
./bin/kms-client --avs-address "0x1234..." --operator-set-id 0 \
  decrypt --app-id "my-application" --encrypted-data encrypted-data.hex \
  --attestation ecdsa --ecdsa-private-key 0xabc123...

# ECDSA key read from a file
./bin/kms-client --avs-address "0x1234..." --operator-set-id 0 \
  decrypt --app-id "my-application" --encrypted-data encrypted-data.hex \
  --attestation ecdsa --ecdsa-private-key-file ./app-key.hex
```

Decrypt flags:

- `--attestation`: attestation method. Empty (default) uses the
  unauthenticated `/app/sign` endpoint; `ecdsa` uses ECDSA challenge-response
  attestation against `/secrets`.
- `--ecdsa-private-key`: hex-encoded secp256k1 private key (an optional `0x`
  prefix is accepted). Takes priority over `--ecdsa-private-key-file`.
- `--ecdsa-private-key-file`: path to a file containing the hex-encoded key.
  Used when `--ecdsa-private-key` is not set.

When `--attestation ecdsa` is set, at least one of `--ecdsa-private-key` or
`--ecdsa-private-key-file` is required.

**Prerequisites for the attested path** (stricter than the default
`/app/sign` flow):

- Operators must run with ECDSA attestation enabled
  (`--enable-ecdsa-attestation=true`).
- The application must exist on-chain — the operator fetches the app's release
  while serving the request.

**Security caveat:** ECDSA attestation proves only ownership of the ECDSA
private key and the freshness of the challenge. It does **not** prove a TEE
execution environment, and the operator does not bind the ECDSA address to the
application ID. The recovered application key is derived solely from the
application ID, so it is identical regardless of which ECDSA key is presented.
Use ECDSA attestation for development and for operators configured to require
it — not as a production confidentiality guarantee. For production, use a TEE
attestation method (GCP Confidential Space / Intel Trust Authority).
````

- [ ] **Step 2: Update the "How It Works" decrypt note**

In `cmd/kmsClient/README.md`, the line under "CLI Tool (This Binary)" currently reads:

```markdown
4. **Decryption**: Collects partial signatures from `/app/sign` endpoint (no attestation required)
```

Replace it with:

```markdown
4. **Decryption**: Collects partial signatures from the `/app/sign` endpoint (no attestation) by default, or from the attested `/secrets` endpoint when `--attestation ecdsa` is set
```

And replace the line:

```markdown
**Note**: The CLI decrypt command uses `/app/sign` which does NOT require attestation.
```

with:

```markdown
**Note**: By default the CLI decrypt command uses `/app/sign`, which does NOT require attestation. Pass `--attestation ecdsa` to use the attested `/secrets` endpoint instead.
```

- [ ] **Step 3: Verify the docs match the code**

Run:
```bash
grep -n "attestation\|ecdsa-private-key" cmd/kmsClient/README.md
```
Expected: the new flag names appear and exactly match those added to the `decrypt` command in Task 2 (`--attestation`, `--ecdsa-private-key`, `--ecdsa-private-key-file`).

- [ ] **Step 4: Commit**

```bash
git add cmd/kmsClient/README.md
git commit -m "docs(kmsClient): document ECDSA-attested decrypt mode"
```

---

## Self-Review

**Spec coverage:**
- New `--attestation` / `--ecdsa-private-key` / `--ecdsa-private-key-file` flags → Task 2 Step 1. ✓
- `--ecdsa-private-key` priority over file; at least one required → Task 1 (`loadECDSAKey`) + tests. ✓
- Unset attestation = unchanged `/app/sign` → Task 2 `decryptWithoutAttestation`. ✓
- `ecdsa` path: load key → ephemeral RSA → `RetrieveSecretsWithOptions` → `DecryptForApp` → shared output → Task 2 `decryptWithECDSAAttestation`. ✓
- Unknown method = usage error → Task 2 `decryptCommand` switch. ✓
- 0x prefix + whitespace tolerance, `HexToECDSA` parsing → Task 1 helper + tests. ✓
- Reuse existing `--threshold`/`--output`/`writeSecretFile`/`prepareOutputPath` → Task 2 shared tail. ✓
- Unit tests for key loading → Task 1 Step 1. ✓
- README docs (flags, prerequisites, security caveat) → Task 3. ✓
- No library changes → all tasks confined to `cmd/kmsClient/`. ✓

**Placeholder scan:** No TBD/TODO/"handle edge cases"/"similar to" — every code and test step shows full content. ✓

**Type consistency:** `loadECDSAKey(keyHex, keyFile string) (*ecdsa.PrivateKey, error)` defined in Task 1 and consumed verbatim in Task 2's `decryptWithECDSAAttestation`. `crypto.DecryptForApp(appID string, appPrivateKey types.G1Point, ciphertext []byte) ([]byte, error)` is called with `result.AppPrivateKey` (a `types.G1Point` value, matching the value parameter). `encryption.GenerateKeyPair(2048)` returns `(privPEM, pubPEM []byte, err error)`, fed to `RSAPrivateKeyPEM`/`RSAPublicKeyPEM` (`[]byte`). `SecretsOptions` field names (`AttestationMethod`, `ECDSAPrivateKey`, `RSAPrivateKeyPEM`, `RSAPublicKeyPEM`) match the struct in `pkg/clients/kmsClient/client.go`. ✓
