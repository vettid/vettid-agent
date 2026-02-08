#!/usr/bin/env bash
set -euo pipefail

# Cross-platform build script for VettID Agent Connector
# Usage: ./scripts/build.sh [target_os/target_arch]
# Example: ./scripts/build.sh linux/amd64

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

BINARY_NAME="vettid-agent"
VERSION="${VERSION:-$(git -C "$ROOT_DIR" describe --tags --always --dirty 2>/dev/null || echo "dev")}"
COMMIT="${COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")}"
BUILD_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

LDFLAGS="-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}"

PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

build_single() {
    local os_arch="$1"
    local os="${os_arch%%/*}"
    local arch="${os_arch##*/}"
    local output="${ROOT_DIR}/dist/${BINARY_NAME}-${os}-${arch}"

    if [ "$os" = "windows" ]; then
        output="${output}.exe"
    fi

    echo "Building ${os}/${arch}..."
    GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build \
        -ldflags "$LDFLAGS" \
        -o "$output" \
        "${ROOT_DIR}/cmd/vettid-agent"

    echo "  -> $(basename "$output")"
}

if [ $# -eq 1 ]; then
    mkdir -p "${ROOT_DIR}/dist"
    build_single "$1"
else
    mkdir -p "${ROOT_DIR}/dist"
    for platform in "${PLATFORMS[@]}"; do
        build_single "$platform"
    done

    echo ""
    echo "Generating checksums..."
    cd "${ROOT_DIR}/dist"
    sha256sum ${BINARY_NAME}-* > checksums.txt
    echo "Done. Binaries in dist/"
fi
