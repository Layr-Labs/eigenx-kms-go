# kmsClient CLI: `--environment` connection presets

**Date:** 2026-06-23
**Status:** Approved
**Scope:** `cmd/kmsClient/` only — no library or `pkg/` changes.

## Problem

Every `kms-client` invocation requires the user to pass `--avs-address` (and
usually `--operator-set-id`) explicitly. These values are fixed per deployment
network, so re-typing them on every call is tedious and error-prone. We want a
named-environment shortcut that fills these connection defaults.

## Goal

Add a global `--environment` (alias `-e`) flag to the `kms-client` CLI. When set
to a known environment name, it supplies default values for `--avs-address` and
`--operator-set-id`. Start with a single environment, `sepolia`, sourced from
the operator chart values
(`eigenx-kms-operator/charts/eigenx-kms/preprod-sepolia/values-preprodSepoliaOperator1.yaml`).

Non-goals:
- No changes to any other binary (`kmsServer`, `registerOperator`, etc.).
- No reuse of / change to `pkg/config`.
- The RPC URL is NOT part of the preset (see below).

## Why the RPC URL is excluded

The values file's `KMS_RPC_URL` and `KMS_BASE_RPC_URL` embed QuickNode API keys
(credentials) in the URL path. Committing those into source would publish
working credentials to the repository and its history. The `sepolia` preset
therefore contains only the non-secret values (`avs-address`,
`operator-set-id`). The user still supplies `--rpc-url` (which keeps its current
`http://localhost:8545` default).

## CLI surface

A new global flag (alongside `--rpc-url`, `--avs-address`, `--operator-set-id`):

- `--environment`, alias `-e` (string, default `""`): named connection preset.
  Empty selects today's behavior (no preset). A known name fills connection
  defaults. An unknown name is a usage error listing the supported names.

`--avs-address` loses its `Required: true` attribute. It becomes required only
when no `--environment` provides it.

### Precedence: explicit flag overrides preset

For each connection value the resolution order is:

1. The value explicitly passed on the command line (detected via
   `cli.Context.IsSet`).
2. The environment preset's value (if `--environment` is set to a known name).
3. The built-in fallback.

| invocation | avs-address | operator-set-id |
|---|---|---|
| `--environment sepolia` | `0x47c9806e7DC4e6fE9a0a2399831F32d06DaE5730` | 0 |
| `--environment sepolia --avs-address 0xABC` | `0xABC` | 0 |
| `--environment sepolia --operator-set-id 2` | `0x47c9…5730` | 2 |
| `--avs-address 0xABC` (no environment) | `0xABC` | 0 |
| neither | — → error | 0 |

- `avs-address`: explicit → preset → else error
  `avs-address is required (provide --avs-address or --environment)`.
- `operator-set-id`: explicit → preset → else `0` (its existing default).
- unknown `--environment`: error
  `unknown environment "<x>": supported environments are: sepolia`.

## Architecture

A new file `cmd/kmsClient/environments.go` owns the preset registry and a pure
resolution helper. `createClient` in `main.go` calls the helper to determine the
effective AVS address and operator-set id before constructing the KMS client.

### `cmd/kmsClient/environments.go`

```go
// environment holds the non-secret connection defaults for a named network.
// The RPC URL is intentionally excluded — production RPC URLs embed API-key
// credentials and must not be committed.
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
// comma-separated string for error/usage messages.
func supportedEnvironmentsString() string

// resolveConnection determines the effective AVS address and operator-set id
// from the --environment preset and any explicitly-set flags. Explicitly-set
// flags always win over the preset. avsSet/setIDSet report whether the
// corresponding flag was passed on the command line (cli.Context.IsSet).
func resolveConnection(envName, avsFlag string, avsSet bool, setIDFlag uint32, setIDSet bool) (avsAddress string, operatorSetID uint32, err error)
```

`resolveConnection` is pure (no CLI dependency) so it is directly unit-testable.

### `cmd/kmsClient/main.go` changes

1. Add the `--environment` / `-e` global flag.
2. Remove `Required: true` from the `--avs-address` global flag.
3. In `createClient`, replace the direct reads of `c.String("avs-address")` /
   `c.Uint("operator-set-id")` with a call to `resolveConnection`, passing
   `c.IsSet("avs-address")` and `c.IsSet("operator-set-id")`.

## Error handling

- Unknown `--environment` value → error from `resolveConnection`, surfaced when
  the command runs.
- No avs-address from any source → error from `resolveConnection`.
- These propagate up through `createClient`, which already returns `error`.

## Testing

Unit tests in `cmd/kmsClient/environments_test.go` covering `resolveConnection`:

- `--environment sepolia` alone → preset avs + set id 0.
- explicit `--avs-address` overrides preset.
- explicit `--operator-set-id` overrides preset.
- no environment, explicit avs → that avs, set id from flag/default.
- no environment, no avs → error mentioning `avs-address is required`.
- unknown environment → error mentioning the supported names.
- explicit operator-set-id with no environment → that id.

`supportedEnvironmentsString` is exercised indirectly via the unknown-env error
assertion.

## Documentation

Update `cmd/kmsClient/README.md`:
- Document the `--environment` / `-e` global flag under "Global Options".
- Add a short "Environments" subsection listing `sepolia` and noting that the
  preset fills `--avs-address` and `--operator-set-id` but not `--rpc-url`
  (which the user must still supply), and that explicit flags override the
  preset.
