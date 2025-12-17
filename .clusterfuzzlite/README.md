# ClusterFuzzLite Integration

This directory contains the configuration for [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/), Google's continuous fuzzing solution.

## Overview

ClusterFuzzLite automatically fuzzes the codebase on:
- **Pull Requests**: Quick 10-minute regression check
- **Push to main**: 30-minute fuzzing with corpus updates
- **Daily Schedule**: 4-hour batch fuzzing for deeper coverage
- **Manual Triggers**: Coverage reports and corpus pruning

## Structure

```
.clusterfuzzlite/
├── Dockerfile      # Build environment for fuzzers
├── build.sh        # Script to compile fuzz targets
├── project.yaml    # Project configuration
└── README.md       # This file
```

## Fuzz Targets

The following packages contain fuzz tests:

| Package | Fuzz Targets |
|---------|--------------|
| `pkg/bls` | Polynomial operations, scalar multiplication, signatures |
| `pkg/crypto` | G1/G2 operations, key recovery, encryption |
| `pkg/dkg` | Share generation, verification, Byzantine behavior |
| `pkg/reshare` | Reshare protocol, threshold operations |
| `pkg/encryption` | RSA OAEP encryption/decryption |

## Running Locally

### Build fuzzers locally (requires Docker):

```bash
# Build the fuzzer image
docker build -t eigenx-kms-fuzz -f .clusterfuzzlite/Dockerfile .

# Run a specific fuzzer
docker run -it eigenx-kms-fuzz /out/bls_recover_secret -max_total_time=60
```

### Using native Go fuzzing:

```bash
# Run all fuzzers for 30 minutes each
go test ./pkg/bls -fuzz=Fuzz -fuzztime=30m
go test ./pkg/crypto -fuzz=Fuzz -fuzztime=30m
go test ./pkg/dkg -fuzz=Fuzz -fuzztime=30m
go test ./pkg/reshare -fuzz=Fuzz -fuzztime=30m
go test ./pkg/encryption -fuzz=Fuzz -fuzztime=30m

# Run a specific fuzzer
go test ./pkg/bls -fuzz=FuzzRecoverSecretRoundTrip -fuzztime=10m
```

## Corpus Storage

ClusterFuzzLite stores fuzzing corpus and coverage data in separate branches:
- `clusterfuzz-corpus`: Accumulated test inputs that increase coverage
- `clusterfuzz-coverage`: Coverage reports

## Crash Handling

When a crash is found:
1. ClusterFuzzLite creates a GitHub issue with crash details
2. SARIF reports are uploaded for GitHub Security tab integration
3. Crash reproducers are stored in the corpus branch

## Manual Workflow Triggers

Use the GitHub Actions UI to manually trigger:
- **batch**: Long-running fuzzing session
- **coverage**: Generate coverage reports
- **prune**: Minimize corpus size

## Adding New Fuzz Targets

1. Create a fuzz test following Go's native fuzzing format:

```go
func FuzzMyFunction(f *testing.F) {
    // Add seed corpus
    f.Add([]byte("seed1"))
    f.Add([]byte("seed2"))
    
    f.Fuzz(func(t *testing.T, data []byte) {
        // Test logic here
    })
}
```

2. Add the target to `.clusterfuzzlite/build.sh`:

```bash
compile_native_go_fuzzer github.com/Layr-Labs/eigenx-kms-go/pkg/mypackage FuzzMyFunction mypackage_my_function
```

3. The fuzzer will be automatically picked up on the next CI run.

## Security

Found a security issue? Please report it responsibly to security@layr.io

