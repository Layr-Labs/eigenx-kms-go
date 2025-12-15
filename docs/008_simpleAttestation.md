# Requirements

For this feature, we want to modify the KMS server to support attesting through multiple means rather than JUST GPC. This will involve:

- Refactoring the Node package to support support multiple attestation methods.
- Update the webserver endpoint to accept attestation method as a parameter.
- Add support for a simple ECDSA based attestation method where the client signs a challenge with their private key and provides the signature along with their public key and the payload that was signed.
- Runtime flags to enable/disable attestation methods
  - e.g. `--enable-gpc-attestation`, `--enable-ecdsa-attestation`
- Update documentation to reflect the new attestation methods and how to use them.

# Execution

## Milestone 1: Refactor Attestation Architecture ✅
**Goal**: Create pluggable attestation system supporting multiple methods

### Tasks:
- [x] 1.1 Create attestation method interface in `pkg/attestation/`
  - Define `AttestationMethod` interface with `Verify(request) (claims, error)` method
  - Define common `AttestationRequest` and `AttestationClaims` types
  - **Created**: `pkg/attestation/method.go`

- [x] 1.2 Refactor existing GCP attestation to implement new interface
  - Create `GCPAttestationMethod` struct wrapping `AttestationVerifier`
  - Implement interface methods
  - Maintain backward compatibility with existing `ProductionVerifier`
  - **Created**: `pkg/attestation/gcp_method.go`
  - **Updated**: `pkg/attestation/verifier.go` (added `ManagerVerifier` adapter)

- [x] 1.3 Create attestation registry/manager
  - Create `AttestationManager` that holds map of enabled methods
  - Add `RegisterMethod(name string, method AttestationMethod)` function
  - Add `VerifyWithMethod(method string, request) (claims, error)` function
  - **Created**: `pkg/attestation/manager.go`
  - **Tests**: `pkg/attestation/manager_test.go`, `pkg/attestation/gcp_method_test.go`

## Milestone 2: Implement ECDSA Attestation Method
**Goal**: Add simple ECDSA-based attestation as alternative to GPC

### Tasks:
- [ ] 2.1 Design ECDSA attestation protocol
  - Define request format: `{ challenge, signature, publicKey, appID }`
  - Challenge format: timestamp + nonce to prevent replay
  - Document security properties and threat model

- [ ] 2.2 Implement `ECDSAAttestationMethod`
  - Create `pkg/attestation/ecdsa.go`
  - Implement signature verification using ECDSA
  - Validate challenge freshness (timestamp within acceptable window)
  - Extract app ID from signed payload
  - Return standardized `AttestationClaims`

- [ ] 2.3 Add unit tests for ECDSA attestation
  - Test valid signature verification
  - Test invalid signature rejection
  - Test expired challenge rejection
  - Test malformed request handling

## Milestone 3: Update Web Server Endpoints
**Goal**: Modify `/secrets` endpoint to accept attestation method parameter

### Tasks:
- [ ] 3.1 Update `SecretsRequestV1` type in `pkg/types/types.go`
  - Add `AttestationMethod string` field (default: "gpc")
  - Keep existing `Attestation []byte` field for attestation data

- [ ] 3.2 Modify `handleSecretsRequest` in `pkg/node/handlers.go`
  - Extract `attestationMethod` from request
  - Pass to `AttestationManager.VerifyWithMethod()`
  - Handle method-not-found errors gracefully
  - Maintain existing flow after verification

- [ ] 3.3 Update endpoint documentation in code comments
  - Document new `attestationMethod` parameter
  - Provide examples for both GPC and ECDSA methods

## Milestone 4: Add Runtime Configuration
**Goal**: Enable/disable attestation methods via command-line flags

### Tasks:
- [ ] 4.1 Add CLI flags to `cmd/kmsServer/main.go`
  - Add `--enable-gpc-attestation` flag (default: true)
  - Add `--enable-ecdsa-attestation` flag (default: false)
  - Add corresponding environment variables

- [ ] 4.2 Update Node initialization
  - Pass enabled methods to `AttestationManager` during setup
  - Register only enabled methods with manager
  - Log which methods are active at startup

- [ ] 4.3 Add validation
  - Ensure at least one method is enabled
  - Fail fast with clear error if no methods enabled

## Milestone 5: Update Client Library and Documentation
**Goal**: Update KMS client to support multiple attestation methods

### Tasks:
- [ ] 5.1 Update `kmsClient` in `cmd/kmsClient/main.go`
  - Add `--attestation-method` flag (default: "gpc")
  - Update request construction to include method
  - Add validation for method parameter

- [ ] 5.2 Create ECDSA attestation example
  - Add example script showing ECDSA attestation flow
  - Document challenge generation
  - Show signature creation and verification

- [ ] 5.3 Update documentation
  - Update `CLAUDE.md` with attestation method information
  - Add section to README explaining both methods
  - Document security considerations for each method
  - Add migration guide for existing deployments

## Milestone 6: Integration Testing
**Goal**: Verify end-to-end functionality of both attestation methods

### Tasks:
- [ ] 6.1 Add integration tests in `internal/tests/integration/`
  - Test `/secrets` with GPC attestation
  - Test `/secrets` with ECDSA attestation
  - Test method switching
  - Test error cases (disabled method, invalid method)

- [ ] 6.2 Test runtime configuration
  - Test with only GPC enabled
  - Test with only ECDSA enabled
  - Test with both enabled
  - Test with neither enabled (should fail)

- [ ] 6.3 Performance testing
  - Benchmark attestation verification overhead
  - Compare GPC vs ECDSA performance
  - Document performance characteristics

## Progress Tracking
- Milestone 1: ✅ **Complete** (Created pluggable attestation architecture)
- Milestone 2: Not started
- Milestone 3: Not started
- Milestone 4: Not started
- Milestone 5: Not started
- Milestone 6: Not started
