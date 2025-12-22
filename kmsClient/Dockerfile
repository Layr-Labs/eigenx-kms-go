FROM golang:1.24.2-bookworm AS builder

RUN apt-get update && apt-get install -y \
    make \
    && rm -rf /var/lib/apt/lists/*

# Assumes the repo root as the context
COPY . /build

WORKDIR /build

RUN make cmd/kmsClient

# Copy all binaries to a known location
RUN cp bin/* /usr/local/bin/

FROM debian:stable-slim

# Install any runtime dependencies if needed
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder stage
COPY --from=builder /usr/local/bin/kms-client /usr/local/bin/

# Make sure the binary is executable (should be, but just in case)
RUN chmod +x /usr/local/bin/kms-client

# Use ENTRYPOINT instead of CMD to allow subcommands to be passed
ENTRYPOINT ["/usr/local/bin/kms-client"]

# Optionally provide a default subcommand
# CMD ["--help"]
