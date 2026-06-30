# kmsClient `--environment` Preset Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a global `--environment`/`-e` flag to `kms-client` that fills `--avs-address` and `--operator-set-id` defaults from a named preset (starting with `sepolia`), with explicitly-passed flags taking priority.

**Architecture:** A new file `cmd/kmsClient/environments.go` owns a preset registry (`map[string]environment`) and a pure `resolveConnection` helper. `createClient` in `main.go` calls that helper — passing `cli.Context.IsSet` results — to compute the effective AVS address and operator-set id before building the KMS client. `--avs-address` loses its hard `Required: true`; it becomes required only when no preset supplies it.

**Tech Stack:** Go, `urfave/cli/v2`.

## Global Constraints

- All changes live in `cmd/kmsClient/` plus its README. No `pkg/` or other-binary changes. Do NOT reuse or modify `pkg/config`.
- The RPC URL is NEVER part of any preset (production RPC URLs embed API-key credentials). Presets carry only `avs-address` and `operator-set-id`.
- Precedence is: explicit flag → preset value → built-in fallback. Explicit flags always win.
- The only registered environment is `sepolia` → `{AVSAddress: "0x47c9806e7DC4e6fE9a0a2399831F32d06DaE5730", OperatorSetID: 0}`.
- Run tests via `./scripts/goTest.sh ./cmd/kmsClient/ ...` (NOT `go test` directly). The script starts web3signer docker containers, then forwards args to `go test -timeout 10m`.
- Build with an explicit output path: `go build -o /tmp/kms-client ./cmd/kmsClient/` (a bare `go build ./cmd/kmsClient/` collides with the `kmsClient` directory name).
- Commits must NOT include any `Co-Authored-By` trailer.

---

## File Structure

- `cmd/kmsClient/environments.go` — Create: the `environment` struct, the `environments` registry, `supportedEnvironmentsString()`, and the pure `resolveConnection(...)` helper.
- `cmd/kmsClient/environments_test.go` — Create: table-driven tests for `resolveConnection`.
- `cmd/kmsClient/main.go` — Modify: add the `--environment`/`-e` global flag, drop `Required: true` from `--avs-address`, and route `createClient` through `resolveConnection`.
- `cmd/kmsClient/README.md` — Modify: document the new flag and the `sepolia` environment.

---

### Task 1: Environment registry and `resolveConnection` helper

**Files:**
- Create: `cmd/kmsClient/environments.go`
- Create: `cmd/kmsClient/environments_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `type environment struct { AVSAddress string; OperatorSetID uint32 }`
  - `var environments map[string]environment` (contains `"sepolia"`).
  - `func supportedEnvironmentsString() string` — sorted, comma-separated known names.
  - `func resolveConnection(envName, avsFlag string, avsSet bool, setIDFlag uint32, setIDSet bool) (avsAddress string, operatorSetID uint32, err error)` — explicit flags win over preset; errors on unknown env or missing avs.

- [ ] **Step 1: Write the failing tests**

Create `cmd/kmsClient/environments_test.go`:

```go
package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveConnection(t *testing.T) {
	const sepoliaAVS = "0x47c9806e7DC4e6fE9a0a2399831F32d06DaE5730"

	t.Run("environment preset fills avs and operator-set-id", func(t *testing.T) {
		avs, setID, err := resolveConnection("sepolia", "", false, 0, false)
		require.NoError(t, err)
		require.Equal(t, sepoliaAVS, avs)
		require.Equal(t, uint32(0), setID)
	})

	t.Run("explicit avs-address overrides preset", func(t *testing.T) {
		avs, setID, err := resolveConnection("sepolia", "0xABC", true, 0, false)
		require.NoError(t, err)
		require.Equal(t, "0xABC", avs)
		require.Equal(t, uint32(0), setID)
	})

	t.Run("explicit operator-set-id overrides preset", func(t *testing.T) {
		avs, setID, err := resolveConnection("sepolia", "", false, 2, true)
		require.NoError(t, err)
		require.Equal(t, sepoliaAVS, avs)
		require.Equal(t, uint32(2), setID)
	})

	t.Run("no environment, explicit avs is used", func(t *testing.T) {
		avs, setID, err := resolveConnection("", "0xABC", true, 0, false)
		require.NoError(t, err)
		require.Equal(t, "0xABC", avs)
		require.Equal(t, uint32(0), setID)
	})

	t.Run("no environment, explicit operator-set-id is used", func(t *testing.T) {
		avs, setID, err := resolveConnection("", "0xABC", true, 5, true)
		require.NoError(t, err)
		require.Equal(t, "0xABC", avs)
		require.Equal(t, uint32(5), setID)
	})

	t.Run("no environment and no avs is an error", func(t *testing.T) {
		_, _, err := resolveConnection("", "", false, 0, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "avs-address is required")
	})

	t.Run("unknown environment is an error listing supported names", func(t *testing.T) {
		_, _, err := resolveConnection("mainnet", "", false, 0, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown environment")
		require.Contains(t, err.Error(), "sepolia")
	})
}

func TestSupportedEnvironmentsString(t *testing.T) {
	got := supportedEnvironmentsString()
	require.True(t, strings.Contains(got, "sepolia"), "should list sepolia, got %q", got)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `./scripts/goTest.sh ./cmd/kmsClient/ -run 'TestResolveConnection|TestSupportedEnvironmentsString' -v`
Expected: compile failure — `undefined: resolveConnection` and `undefined: supportedEnvironmentsString`.

- [ ] **Step 3: Implement `environments.go`**

Create `cmd/kmsClient/environments.go`:

```go
package main

import (
	"fmt"
	"sort"
	"strings"
)

// environment holds the non-secret connection defaults for a named network.
// The RPC URL is intentionally excluded — production RPC URLs embed API-key
// credentials and must not be committed. Users still supply --rpc-url.
type environment struct {
	AVSAddress    string
	OperatorSetID uint32
}

// environments is the registry of known connection presets, selected via
// --environment. Values are sourced from the operator deployment charts.
var environments = map[string]environment{
	"sepolia": {
		AVSAddress:    "0x47c9806e7DC4e6fE9a0a2399831F32d06DaE5730",
		OperatorSetID: 0,
	},
}

// supportedEnvironmentsString returns the known environment names as a sorted,
// comma-separated string for error and usage messages.
func supportedEnvironmentsString() string {
	names := make([]string, 0, len(environments))
	for name := range environments {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// resolveConnection determines the effective AVS address and operator-set id
// from the --environment preset and any explicitly-set flags. Explicitly-set
// flags always win over the preset; the preset wins over the built-in default.
// avsSet/setIDSet report whether the corresponding flag was passed on the
// command line (cli.Context.IsSet).
//
// Resolution:
//   - avs-address: explicit flag → preset → else error.
//   - operator-set-id: explicit flag → preset → else 0.
func resolveConnection(envName, avsFlag string, avsSet bool, setIDFlag uint32, setIDSet bool) (string, uint32, error) {
	var preset environment
	havePreset := false
	if envName != "" {
		p, ok := environments[envName]
		if !ok {
			return "", 0, fmt.Errorf("unknown environment %q: supported environments are: %s", envName, supportedEnvironmentsString())
		}
		preset = p
		havePreset = true
	}

	// Resolve AVS address: explicit flag wins, then preset, else error.
	avsAddress := ""
	switch {
	case avsSet:
		avsAddress = avsFlag
	case havePreset:
		avsAddress = preset.AVSAddress
	default:
		return "", 0, fmt.Errorf("avs-address is required (provide --avs-address or --environment)")
	}

	// Resolve operator-set id: explicit flag wins, then preset, else 0.
	var operatorSetID uint32
	switch {
	case setIDSet:
		operatorSetID = setIDFlag
	case havePreset:
		operatorSetID = preset.OperatorSetID
	default:
		operatorSetID = 0
	}

	return avsAddress, operatorSetID, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `./scripts/goTest.sh ./cmd/kmsClient/ -run 'TestResolveConnection|TestSupportedEnvironmentsString' -v`
Expected: PASS — all subtests of `TestResolveConnection` and `TestSupportedEnvironmentsString` green.

- [ ] **Step 5: Commit**

```bash
git add cmd/kmsClient/environments.go cmd/kmsClient/environments_test.go
git commit -m "feat(kmsClient): add environment connection presets"
```

---

### Task 2: Wire `--environment` into the CLI

**Files:**
- Modify: `cmd/kmsClient/main.go` (global flags + `createClient`)

**Interfaces:**
- Consumes: `resolveConnection(envName, avsFlag string, avsSet bool, setIDFlag uint32, setIDSet bool) (string, uint32, error)` from Task 1.
- Produces: a global `--environment`/`-e` flag; `createClient` resolves connection values through `resolveConnection`.

- [ ] **Step 1: Add the `--environment` flag and drop `Required` on `--avs-address`**

In `cmd/kmsClient/main.go`, the global `Flags` slice currently reads (around lines 35-50):

```go
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "rpc-url",
				Usage: "Ethereum RPC URL",
				Value: "http://localhost:8545",
			},
			&cli.StringFlag{
				Name:     "avs-address",
				Usage:    "AVS contract address",
				Required: true,
			},
			&cli.UintFlag{
				Name:  "operator-set-id",
				Usage: "Operator set ID",
				Value: 0,
			},
```

Replace that block with (adds `--environment`, removes `Required: true`, and notes the preset interaction in usage text):

```go
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "environment",
				Aliases: []string{"e"},
				Usage:   "Named connection preset that fills --avs-address and --operator-set-id (e.g. \"sepolia\"). Explicit flags override the preset. The RPC URL is never part of a preset.",
				Value:   "",
			},
			&cli.StringFlag{
				Name:  "rpc-url",
				Usage: "Ethereum RPC URL",
				Value: "http://localhost:8545",
			},
			&cli.StringFlag{
				Name:  "avs-address",
				Usage: "AVS contract address (required unless provided by --environment)",
			},
			&cli.UintFlag{
				Name:  "operator-set-id",
				Usage: "Operator set ID",
				Value: 0,
			},
```

- [ ] **Step 2: Route `createClient` through `resolveConnection`**

In `cmd/kmsClient/main.go`, `createClient` currently builds the config like this (around lines 160-168):

```go
	// Create KMS client with injected dependencies
	config := &kmsClient.ClientConfig{
		AVSAddress:     c.String("avs-address"),
		OperatorSetID:  uint32(c.Uint("operator-set-id")),
		Logger:         zapLogger,
		ContractCaller: contractCaller,
	}
```

Replace those four assignment lines so the AVS address and operator-set id come
from `resolveConnection`. The full replacement (resolve first, then build the
config) is:

```go
	// Resolve connection details from the --environment preset and any
	// explicitly-set flags (explicit flags win over the preset).
	avsAddress, operatorSetID, err := resolveConnection(
		c.String("environment"),
		c.String("avs-address"),
		c.IsSet("avs-address"),
		uint32(c.Uint("operator-set-id")),
		c.IsSet("operator-set-id"),
	)
	if err != nil {
		return nil, err
	}

	// Create KMS client with injected dependencies
	config := &kmsClient.ClientConfig{
		AVSAddress:     avsAddress,
		OperatorSetID:  operatorSetID,
		Logger:         zapLogger,
		ContractCaller: contractCaller,
	}
```

Note: `createClient` already declares `err` earlier in the function (from the
logger/eth-client setup), so use `=` for the `resolveConnection` assignment if
the linter flags a redeclaration. If `err` is not in scope at that point in your
copy of the file, use `:=`. Verify by building in Step 3.

- [ ] **Step 3: Build to verify it compiles**

Run: `go build -o /tmp/kms-client ./cmd/kmsClient/`
Expected: no output, exit 0.

- [ ] **Step 4: Verify the global flag appears in help**

Run: `/tmp/kms-client --help`
Expected: the GLOBAL OPTIONS list includes `--environment value, -e value` with the preset usage text, alongside `--rpc-url`, `--avs-address`, `--operator-set-id`.

- [ ] **Step 5: Verify the preset resolves end-to-end via an expected error path**

This confirms the wiring without needing a live operator set. With `--environment sepolia` the AVS address is supplied by the preset, so `createClient` succeeds and the command proceeds to the chain call (which fails on the localhost RPC — that is the expected, correct downstream failure, proving avs-address was NOT the blocker):

Run:
```bash
/tmp/kms-client --environment sepolia get-pubkey --app-id demo 2>&1 | head -5
```
Expected: output shows it got past flag resolution — i.e. it prints the
`🔑 Getting public key for app: demo` line and then fails fetching operators /
connecting to `localhost:8545`, NOT a "avs-address is required" error.

Then confirm the negative case still errors:
```bash
/tmp/kms-client get-pubkey --app-id demo 2>&1 | head -5
```
Expected: error containing `avs-address is required`.

- [ ] **Step 6: Run the full package test suite**

Run: `./scripts/goTest.sh ./cmd/kmsClient/ -v`
Expected: PASS — `TestResolveConnection`, `TestSupportedEnvironmentsString`, `TestLoadECDSAKey`, `TestWriteSecretFile`, `TestPrepareOutputPath` all green.

- [ ] **Step 7: Commit**

```bash
git add cmd/kmsClient/main.go
git commit -m "feat(kmsClient): wire --environment preset into client setup"
```

---

### Task 3: Document the `--environment` flag

**Files:**
- Modify: `cmd/kmsClient/README.md`

**Interfaces:**
- Consumes: the flag and behavior from Tasks 1-2.
- Produces: user-facing docs (no code interface).

- [ ] **Step 1: Add an Environments subsection and document the global flag**

In `cmd/kmsClient/README.md`, the "Global Options" section currently reads:

```markdown
## Global Options

- `--rpc-url`: Ethereum RPC endpoint (default: http://localhost:8545)
- `--avs-address`: AVS contract address (required)
- `--operator-set-id`: Operator set ID to use (default: 0)

All commands automatically discover and interact with the current operator set from the blockchain.
```

Replace it with:

```markdown
## Global Options

- `--environment`, `-e`: named connection preset that fills `--avs-address` and `--operator-set-id` (e.g. `sepolia`). Explicit flags override the preset. The RPC URL is never part of a preset.
- `--rpc-url`: Ethereum RPC endpoint (default: http://localhost:8545)
- `--avs-address`: AVS contract address (required unless provided by `--environment`)
- `--operator-set-id`: Operator set ID to use (default: 0)

All commands automatically discover and interact with the current operator set from the blockchain.

### Environments

`--environment` (alias `-e`) selects a named connection preset so you don't have
to pass `--avs-address`/`--operator-set-id` on every call:

| Environment | avs-address | operator-set-id |
|-------------|-------------|-----------------|
| `sepolia`   | `0x47c9806e7DC4e6fE9a0a2399831F32d06DaE5730` | `0` |

The preset supplies only `--avs-address` and `--operator-set-id`. It does **not**
set `--rpc-url` — production RPC URLs embed API-key credentials, so you must
still pass your own `--rpc-url`. Any flag you pass explicitly overrides the
preset value.

```bash
# Use the sepolia preset; supply your own RPC URL
./bin/kms-client --environment sepolia \
  --rpc-url "https://eth-sepolia.example/v2/<key>" \
  get-pubkey --app-id "my-application"

# Override the preset's operator-set-id
./bin/kms-client -e sepolia --operator-set-id 1 \
  --rpc-url "https://eth-sepolia.example/v2/<key>" \
  get-pubkey --app-id "my-application"
```
```

- [ ] **Step 2: Verify the docs match the code**

Run: `grep -n "environment\|sepolia\|0x47c9806e7DC4e6fE9a0a2399831F32d06DaE5730" cmd/kmsClient/README.md`
Expected: the flag name `--environment`, the alias `-e`, the `sepolia` name, and the AVS address all appear and match the registry value in `environments.go`.

- [ ] **Step 3: Commit**

```bash
git add cmd/kmsClient/README.md
git commit -m "docs(kmsClient): document --environment connection presets"
```

---

## Self-Review

**Spec coverage:**
- Global `--environment`/`-e` flag → Task 2 Step 1. ✓
- `sepolia` preset with the chart's avs-address + operator-set-id, RPC excluded → Task 1 `environments` registry. ✓
- Precedence (explicit flag → preset → fallback) → Task 1 `resolveConnection` + tests. ✓
- `--avs-address` no longer hard-required → Task 2 Step 1 (drops `Required: true`). ✓
- avs-address required only when no preset supplies it; error text → Task 1 helper + test. ✓
- Unknown environment errors listing supported names → Task 1 helper + test. ✓
- operator-set-id default 0 retained → Task 1 helper + test. ✓
- `createClient` routes through the helper using `c.IsSet` → Task 2 Step 2. ✓
- Unit tests for `resolveConnection` → Task 1 Step 1. ✓
- README docs (Global Options + Environments) → Task 3. ✓
- Scope confined to `cmd/kmsClient/` → all tasks. ✓

**Placeholder scan:** No TBD/TODO/"handle edge cases"/"similar to"; every code and test step has full content. ✓

**Type consistency:** `resolveConnection(envName, avsFlag string, avsSet bool, setIDFlag uint32, setIDSet bool) (string, uint32, error)` is defined in Task 1 and called with exactly that argument order/types in Task 2 Step 2 (`c.String("environment")`, `c.String("avs-address")`, `c.IsSet("avs-address")`, `uint32(c.Uint("operator-set-id"))`, `c.IsSet("operator-set-id")`). `environment{AVSAddress string, OperatorSetID uint32}` matches the `kmsClient.ClientConfig` fields `AVSAddress string` / `OperatorSetID uint32` consumed in Task 2. ✓
