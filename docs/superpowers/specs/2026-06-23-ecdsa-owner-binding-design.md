# Owner-bound ECDSA attestation (no release requirement)

**Date:** 2026-06-23
**Status:** Approved
**Scope:** `pkg/node/handlers.go` (the `/secrets` ECDSA path) + test helpers + docs. No change to `pkg/attestation/ecdsa.go`.
**Branch:** `feat/kmsclient-ecdsa-attestation` (same branch as the client work).

## Problem

ECDSA attestation on the `/secrets` endpoint authenticates nothing app-specific.
The server verifies that the request signature matches the **client-supplied**
public key (`pkg/attestation/ecdsa.go` `Verify`, lines 169-171), but never ties
that key to the application. Because an `appID` is an app **contract address**
with no private key, "prove you control a key" is satisfied by any freshly
generated keypair. Anyone can therefore request any app's key material over the
ECDSA path.

Separately, the ECDSA path currently requires an on-chain release
(`GetLatestReleaseAsRelease`, returns `404 Release not found` when absent) and
then enforces an image-digest check. ECDSA sets `ImageDigest = "ecdsa:unverified"`,
which never matches a real release digest — so ECDSA against any real app
**already fails today** (404 if no release, 403 if a release exists). ECDSA is
meant to be an easy testing method and should not depend on a release at all.

## Goal

For the ECDSA attestation method on `/secrets`:

1. **Bind to the app creator.** Require that the ECDSA signer address equals the
   app's on-chain creator (`GetAppCreator(appID)`). This replaces "prove you
   control some key" with "prove you control the app creator's key."
2. **Drop the release requirement.** Do not 404 when there is no release. Do not
   run the digest / registry / container-policy checks for ECDSA.
3. **Best-effort env.** If a release exists and has env, return its
   `encrypted_env` / `public_env`. Otherwise return empty env. Always return the
   partial signature on success.

Non-ECDSA methods (gcp / intel / tpm / eigenx-snp) are **unchanged**: release
still required, digest / registry / container-policy still enforced.

## Background facts (verified against code)

- `claims.PublicKey` is populated by the ECDSA `Verify` and is trustworthy
  post-verification (the signature was checked against it). So the handler can
  derive the signer address without re-verifying anything.
- `IContractCaller.GetAppCreator(app common.Address, opts *bind.CallOpts)
  (common.Address, error)` already exists and is implemented on the node's
  `baseContractCaller` (`pkg/contractCaller/contractCaller.go:89`, impl in
  `caller/eigenCompute.go`).
- The app creator equals the `msg.sender` (an EOA) that deployed/created the app
  on-chain, so a single-address equality check is correct (no multi-signer /
  delegation set for now).
- `appID` is a hex contract address; `common.HexToAddress` plus an
  `common.IsHexAddress` guard converts/validates it.
- `signAppIDWithVersion(appID, keyVersion)` derives the partial signature purely
  from the appID string, independent of any release.

## Design

### Handler control flow (`handleSecretsRequest`)

After `VerifyWithMethod` succeeds and the `claims.AppID == req.AppID` check
passes, branch on `req.AttestationMethod`:

```
if method == "ecdsa":
    release = verifyECDSAOwnershipAndResolveRelease(...)   // new path
else:
    release = (existing flow: GetLatestReleaseAsRelease + digest + registry + container-policy)
# shared tail: key-version lookup → signAppIDWithVersion → RSA-encrypt → respond
```

The shared tail (Steps 6-10 today: key version, sign, serialize, encrypt,
respond) stays common. Only the "obtain `release`" step differs by method.
`release` for the ECDSA path may be a zero-value `*types.Release` (empty env).

### New helper (in `pkg/node/handlers.go`)

```go
// verifyECDSAOwnership confirms the ECDSA attestation signer is the app's
// on-chain creator. appID must be an app contract address. Returns an error
// describing the failure; the caller maps it to the right HTTP status.
func (s *Server) verifyECDSAOwnership(appID string, publicKey []byte) error
```

Logic:
1. `if !common.IsHexAddress(appID)` → error `"app_id must be a contract address for ecdsa attestation"` (caller → 400).
2. Derive signer: `pub, err := ethcrypto.UnmarshalPubkey(publicKey)`; on error → `"invalid ecdsa public key"` (400). `signer := ethcrypto.PubkeyToAddress(*pub)`.
3. `creator, err := s.node.baseContractCaller.GetAppCreator(common.HexToAddress(appID), nil)`; on error → wrapped error (caller → 502).
4. `if signer != creator` → error `"ecdsa signer is not the app creator"` (caller → 403). (Address `==` is already case-insensitive; both are `common.Address`.)

The release resolution for ECDSA is inline in the handler (small):

```go
// best-effort: no release, or empty env, is fine — return empty env.
release, err := s.node.baseContractCaller.GetLatestReleaseAsRelease(r.Context(), req.AppID)
if err != nil {
    release = &types.Release{} // no release → empty env, still serve the share
}
```

So the ECDSA branch is: `verifyECDSAOwnership(...)` (return appropriate HTTP
error on failure) → best-effort release → fall through to the shared signing
tail. No digest / registry / container-policy checks run for ECDSA.

### Imports

`pkg/node/handlers.go` gains `ethcrypto "github.com/ethereum/go-ethereum/crypto"`
(`common` and `types` are already imported).

## Error handling / HTTP statuses (ECDSA path)

| condition | status | message |
|---|---|---|
| appID not a hex address | 400 | `app_id must be a contract address for ecdsa attestation` |
| public key unparseable | 400 | `invalid ecdsa public key` |
| `GetAppCreator` call fails | 502 | `failed to look up app creator` |
| signer != creator | 403 | `ecdsa signer is not the app creator` |
| ownership ok, no release | 200 | share + empty env |
| ownership ok, release w/ env | 200 | share + release env |

## Test helper change

`TestableContractCallerStub` (`pkg/contractCaller/testhelpers.go`) currently
inherits `GetAppCreator` from `MockContractCallerStub` (returns zero address).
Add a configurable creator map and override:

```go
// add field: creators map[string]common.Address  (keyed by app address hex, lowercased)
// add method:
func (m *TestableContractCallerStub) SetAppCreator(app common.Address, creator common.Address)
// override:
func (m *TestableContractCallerStub) GetAppCreator(app common.Address, opts *bind.CallOpts) (common.Address, error)
//   returns the configured creator, or zero address if none set.
```

Initialize the `creators` map in `NewTestableContractCallerStub`.

## Testing

New subtests under `Test_SecretsEndpoint` in `pkg/node/secrets_test.go`, driving
the ECDSA method via the stub attestation manager (`StubECDSAMethod`). Each test
sets the app creator on the stub to match (or not match) the signer derived from
the attestation's public key.

- **ECDSA signer == creator, release with env** → 200, response env equals the
  release env, partial sig present.
- **ECDSA signer == creator, no release** → 200, empty env, partial sig present
  (regression guard for the "no 404" behavior).
- **ECDSA signer == creator, release with empty env** → 200, empty env, sig
  present.
- **ECDSA signer != creator** → 403, body contains `not the app creator`.
- **ECDSA appID not an address** → 400, body contains `contract address`.
- **non-ECDSA method (existing gcp flow) with no release** → still 404
  (regression guard: release requirement intact for non-ECDSA).

The stub ECDSA method must surface `claims.PublicKey` so the handler can derive
the signer; if `StubECDSAMethod` does not already echo the request public key
into claims, the test will set claims' public key to a key whose address is then
configured as the creator. (Confirm `StubECDSAMethod` behavior during planning;
adjust the helper if needed so the public key flows into claims.)

## Documentation

Update `cmd/kmsClient/README.md` ECDSA section: the `--ecdsa-private-key` /
`--ecdsa-private-key-file` must be the **app creator's** key (the EOA that
deployed the app); a random/ephemeral key will be rejected with
`ecdsa signer is not the app creator`. Note that the attested ECDSA path no
longer requires an on-chain release and returns env only if a release exists.
