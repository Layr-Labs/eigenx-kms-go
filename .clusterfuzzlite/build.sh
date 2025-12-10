#!/bin/bash -eu
# ClusterFuzzLite build script for eigenx-kms-go

cd "$SRC/eigenx-kms-go"

# Install the fuzzing build tool
export PATH="$(go env GOPATH)/bin:${PATH}"
go install github.com/AdamKorcz/go-118-fuzz-build@latest

compile_native_go_fuzzer() {
    local pkg=$1
    local func=$2
    local out_name=$3

    if ! go-118-fuzz-build -func "$func" -o "$OUT/$out_name" "$pkg"; then
        echo "Warning: Could not build $out_name"
    fi
}

# BLS package fuzzers
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzRecoverSecretRoundTrip bls_recover_secret
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzScalarMulAddLinearG1 bls_scalar_mul_g1
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzScalarMulAddLinearG2 bls_scalar_mul_g2
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzSignVerifyRoundTripG1 bls_sign_verify_g1
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzSignVerifyRoundTripG2 bls_sign_verify_g2
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzSignVerifyWrongMessageG1 bls_wrong_msg_g1
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzSignVerifyWrongKeyG1 bls_wrong_key_g1
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzAggregateG1Signatures bls_aggregate_g1
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzZeroScalarMultiplication bls_zero_scalar
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzAdditionWithIdentityG1 bls_identity_g1
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzAdditionWithIdentityG2 bls_identity_g2
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzAdditiveInverseG1 bls_inverse_g1
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzAdditiveInverseG2 bls_inverse_g2

# Crypto package fuzzers
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/crypto FuzzAddG1MatchesLibrary crypto_add_g1
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/crypto FuzzAddG2MatchesLibrary crypto_add_g2
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/crypto FuzzRecoverAppPrivateKeyRoundTrip crypto_recover_key
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/crypto FuzzRecoverAppPrivateKeyInsufficientShares crypto_insufficient_shares
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/crypto FuzzEncryptDecryptRoundTrip crypto_encrypt_decrypt
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/crypto FuzzEncryptDecryptWrongAppID crypto_wrong_app

# DKG package fuzzers
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/dkg FuzzGenerateVerifyAndFinalize dkg_generate_verify
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/dkg FuzzVerifyShareRejectsTamperedShare dkg_tampered_share
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/dkg FuzzVerifyShareRejectsCorruptedCommitments dkg_corrupted_commitments
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/dkg FuzzVerifyShareRejectsMismatchedDealerCommitments dkg_mismatched_dealer
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/dkg FuzzThresholdBoundaryConditions dkg_threshold_boundary
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/dkg FuzzVerifyShareWithZeroShare dkg_zero_share
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/dkg FuzzVerifyShareWithEmptyCommitments dkg_empty_commitments
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/dkg FuzzFinalizeWithSubsetOfShares dkg_subset_shares

# Reshare package fuzzers
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/reshare FuzzGenerateVerifyAndComputeNewKeyShare reshare_generate_verify
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/reshare FuzzVerifyShareRejectsTamperedShare reshare_tampered_share
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/reshare FuzzVerifyShareRejectsMismatchedCommitments reshare_mismatched_commitments
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/reshare FuzzComputeNewKeyShareThresholdSubset reshare_threshold_subset

# Encryption package fuzzers
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/encryption FuzzRSAEncryptDecrypt encryption_rsa_roundtrip
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/encryption FuzzRSARejectsWeakKeys encryption_rsa_weak_keys

echo "Build complete. Fuzzers in $OUT:"
ls -la "$OUT/" || true

