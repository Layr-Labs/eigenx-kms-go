#!/bin/bash -euo pipefail
# ClusterFuzzLite build script for eigenx-kms-go

cd "$SRC/eigenx-kms-go"

# Ensure toolchain is available
if ! command -v clang++ >/dev/null 2>&1; then
    apt-get update && apt-get install -y clang
fi
export CXX="${CXX:-clang++}"

# Install the fuzzing build tool
export PATH="$(go env GOPATH)/bin:${PATH}"
export CGO_ENABLED=1
export GOOS=linux
export GOARCH=amd64
# Go 1.24+ tries to stamp VCS info by default; in containerized builds the repo may not have
# usable VCS metadata (or git may be unavailable), which breaks builds.
export GOFLAGS="${GOFLAGS:-} -buildvcs=false"

# Some environments (especially local Docker runs) don't provide $LIB_FUZZING_ENGINE as a
# standalone archive (e.g. /usr/lib/libFuzzingEngine.a). That's OK: clang can link the
# libFuzzer runtime via -fsanitize=fuzzer (we pass -fsanitize=fuzzer,address below).
# Prefer the env provided by the OSS-Fuzz base image, but fall back to a detected path.
if [[ -n "${LIB_FUZZING_ENGINE:-}" && ! -f "${LIB_FUZZING_ENGINE:-}" ]]; then
    unset LIB_FUZZING_ENGINE
fi
if [[ -z "${LIB_FUZZING_ENGINE:-}" ]]; then
    for candidate in \
        /usr/lib/libFuzzingEngine.a \
        /usr/local/lib/libFuzzingEngine.a \
        /usr/lib/llvm-*/lib/libFuzzingEngine.a \
        /usr/local/lib/llvm-*/lib/libFuzzingEngine.a
    do
        # shellcheck disable=SC2086
        found=$(ls -1 $candidate 2>/dev/null | head -n 1 || true)
        if [[ -n "$found" && -f "$found" ]]; then
            export LIB_FUZZING_ENGINE="$found"
            break
        fi
    done
fi

if [[ -z "${LIB_FUZZING_ENGINE:-}" ]]; then
    echo "Warning: libFuzzer engine archive not found; relying on clang's -fsanitize=fuzzer runtime."
fi
go install github.com/AdamKorcz/go-118-fuzz-build@latest
# Ensure the helper testing shim is available
go get github.com/AdamKorcz/go-118-fuzz-build/testing@latest

mkdir -p "$OUT"

# Build a Go fuzz target into a libFuzzer binary
compile_native_go_fuzzer() {
    local pkg=$1
    local func=$2
    local out_name=$3
    # optional="optional" allows best-effort builds without failing the script.
    # default is "required" which fails the build on errors to avoid silently missing fuzzers.
    local optional=${4:-required}

    local tmpdir
    tmpdir=$(mktemp -d)
    local archive="${tmpdir}/${out_name}.a"

    if ! go-118-fuzz-build -func "$func" -o "$archive" "$pkg"; then
        echo "Error: Could not build archive for $out_name"
        rm -rf "$tmpdir"
        if [[ "$optional" == "optional" ]]; then
            echo "Proceeding without optional fuzzer $out_name"
            return 0
        fi
        return 1
    fi

    # Link with sanitizer flags; $CXXFLAGS from base image already includes the selected sanitizer (ASan/UBSan).
    # CXX can include extra flags (e.g., "-lresolv"), so invoke via eval to preserve spacing.
    # Link using clang's sanitizer runtimes; $LIB_FUZZING_ENGINE (if present) is optional.
    link_cmd="$CXX $CXXFLAGS ${LIB_FUZZING_ENGINE:-} -fsanitize=fuzzer,address \"$archive\" -o \"$OUT/$out_name\""
    if ! eval "$link_cmd"; then
        echo "Error: Could not link $out_name"
        rm -rf "$tmpdir"
        if [[ "$optional" == "optional" ]]; then
            echo "Proceeding without optional fuzzer $out_name"
            return 0
        fi
        return 1
    fi

    rm -rf "$tmpdir"
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

# Add missing BLS fuzzers (found in operations_fuzz_test.go but not compiled)
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzDoubleVsAddSelf bls_double_vs_add
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzScalarMultiplicationByOne bls_scalar_one
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/bls FuzzScalarMultiplicationConsistency bls_scalar_consistency

# Copy dictionary files to output for libFuzzer
cp "$SRC/eigenx-kms-go/.clusterfuzzlite/bls.dict" "$OUT/" || true
cp "$SRC/eigenx-kms-go/.clusterfuzzlite/crypto.dict" "$OUT/" || true
cp "$SRC/eigenx-kms-go/.clusterfuzzlite/dkg.dict" "$OUT/" || true
cp "$SRC/eigenx-kms-go/.clusterfuzzlite/ibe.dict" "$OUT/" || true
cp "$SRC/eigenx-kms-go/.clusterfuzzlite/rsa.dict" "$OUT/" || true

# Create symlinks so fuzzers can find their dictionaries
# libFuzzer automatically loads <fuzzer_name>.dict if present
ln -sf crypto.dict "$OUT/crypto_recover_key.dict" || true
ln -sf crypto.dict "$OUT/crypto_add_g1.dict" || true
ln -sf crypto.dict "$OUT/crypto_add_g2.dict" || true
ln -sf crypto.dict "$OUT/crypto_insufficient_shares.dict" || true
ln -sf ibe.dict "$OUT/crypto_encrypt_decrypt.dict" || true
ln -sf ibe.dict "$OUT/crypto_wrong_app.dict" || true

ln -sf dkg.dict "$OUT/dkg_generate_verify.dict" || true
ln -sf dkg.dict "$OUT/dkg_tampered_share.dict" || true
ln -sf dkg.dict "$OUT/dkg_corrupted_commitments.dict" || true
ln -sf dkg.dict "$OUT/dkg_mismatched_dealer.dict" || true
ln -sf dkg.dict "$OUT/dkg_threshold_boundary.dict" || true
ln -sf dkg.dict "$OUT/dkg_zero_share.dict" || true
ln -sf dkg.dict "$OUT/dkg_empty_commitments.dict" || true
ln -sf dkg.dict "$OUT/dkg_subset_shares.dict" || true

ln -sf dkg.dict "$OUT/reshare_generate_verify.dict" || true
ln -sf dkg.dict "$OUT/reshare_tampered_share.dict" || true
ln -sf dkg.dict "$OUT/reshare_mismatched_commitments.dict" || true
ln -sf dkg.dict "$OUT/reshare_threshold_subset.dict" || true

ln -sf bls.dict "$OUT/bls_recover_secret.dict" || true
ln -sf bls.dict "$OUT/bls_scalar_mul_g1.dict" || true
ln -sf bls.dict "$OUT/bls_scalar_mul_g2.dict" || true
ln -sf bls.dict "$OUT/bls_sign_verify_g1.dict" || true
ln -sf bls.dict "$OUT/bls_sign_verify_g2.dict" || true
ln -sf bls.dict "$OUT/bls_wrong_msg_g1.dict" || true
ln -sf bls.dict "$OUT/bls_wrong_key_g1.dict" || true
ln -sf bls.dict "$OUT/bls_aggregate_g1.dict" || true
ln -sf bls.dict "$OUT/bls_zero_scalar.dict" || true
ln -sf bls.dict "$OUT/bls_identity_g1.dict" || true
ln -sf bls.dict "$OUT/bls_identity_g2.dict" || true
ln -sf bls.dict "$OUT/bls_inverse_g1.dict" || true
ln -sf bls.dict "$OUT/bls_inverse_g2.dict" || true
ln -sf bls.dict "$OUT/bls_double_vs_add.dict" || true
ln -sf bls.dict "$OUT/bls_scalar_one.dict" || true
ln -sf bls.dict "$OUT/bls_scalar_consistency.dict" || true

ln -sf rsa.dict "$OUT/encryption_rsa_roundtrip.dict" || true
ln -sf rsa.dict "$OUT/encryption_rsa_weak_keys.dict" || true

echo "Build complete. Fuzzers and dictionaries in $OUT:"
echo "Dictionary files:"
ls -lh "$OUT"/*.dict 2>/dev/null | wc -l
echo "Fuzzer binaries:"
ls -la "$OUT/" || true

# Fail the build if no fuzz targets were produced
if [ -z "$(find "$OUT" -maxdepth 1 -type f -perm -111 -print -quit)" ]; then
    echo "ERROR: No fuzz targets produced in $OUT"
    exit 1
fi

