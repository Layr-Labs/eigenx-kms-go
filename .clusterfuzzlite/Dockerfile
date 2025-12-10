FROM gcr.io/oss-fuzz-base/base-builder-go:v1

# Copy source code
COPY . $SRC/eigenx-kms-go
WORKDIR $SRC/eigenx-kms-go

# Copy build script
COPY .clusterfuzzlite/build.sh $SRC/build.sh

