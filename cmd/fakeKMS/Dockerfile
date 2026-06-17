# Multi-stage build of cmd/fakeKMS into a distroless static image.
# Build context must be the eigenx-kms-go repo root (where go.mod lives).

FROM golang:1.25-bookworm AS builder
WORKDIR /src

# Cache module deps before copying source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO off for a fully static binary; targets linux/amd64 (the cluster
# nodegroup is m6a.xlarge so amd64 is correct).
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build -trimpath -ldflags="-s -w" -o /out/fakeKMS ./cmd/fakeKMS

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/fakeKMS /usr/local/bin/fakeKMS
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/fakeKMS"]
