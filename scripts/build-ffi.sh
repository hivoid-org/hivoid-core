#!/usr/bin/env bash
# HiVoid FFI Shared Library Build Automation
# This script uses Docker to cross-compile shared libraries in a containerized environment.

set -e
set -o pipefail

# Output location: directory where generated binaries will be saved
OUTPUT_DIR="./dist"

echo "----------------------------------------------------------------"
echo "        HiVoid Cross-Platform Shared Library Builder           "
echo "----------------------------------------------------------------"

# 1. Prerequisite Checks
echo "==> Verifying Docker capability..."
if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker is not installed or not in PATH."
    exit 1
fi

# 2. Version Procurement
if [ -z "$VERSION" ]; then
    read -p "Enter build version (default: dev): " INPUT_VERSION
    VERSION=${INPUT_VERSION:-dev}
fi
echo "==> Target Version: ${VERSION}"

# 3. Docker Buildx Setup
BUILDER_NAME="hivoid-ffi-builder"
echo "==> Ensuring Docker Buildx builder instance '${BUILDER_NAME}' exists..."
if ! docker buildx ls | grep -qw "$BUILDER_NAME"; then
    echo "Creating new builder instance..."
    docker buildx create --name "$BUILDER_NAME" --use
else
    echo "Using existing builder instance..."
    docker buildx use "$BUILDER_NAME"
fi

# 4. Preparation
mkdir -p "$OUTPUT_DIR"

# 5. Starting the Build Pipeline
echo "==> Launching Dockerized FFI Build Pipeline (this may take a while)..."
echo "    Preparing Linux, Windows, and Android Shared Libraries..."

docker buildx build \
    --builder "$BUILDER_NAME" \
    --target artifacts \
    --build-arg VERSION="$VERSION" \
    --output type=local,dest="$OUTPUT_DIR" \
    --file docker/Dockerfile.ffi \
    .

# 6. Post-Build: Create a unified SDK zip containing all platform zips
echo "==> Bundling all platform artifacts into a unified SDK zip..."
ABS_OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
SDK_ZIP="${ABS_OUTPUT_DIR}/hivoid-ffi-sdk-${VERSION}.zip"

TMP_SDK_DIR="/tmp/hivoid-sdk-bundle"
rm -rf "$TMP_SDK_DIR"
mkdir -p "$TMP_SDK_DIR"

cp "${ABS_OUTPUT_DIR}"/hivoid-core-*-FFI-${VERSION}.zip "$TMP_SDK_DIR/"

(cd "$TMP_SDK_DIR" && zip -q "${SDK_ZIP}" *)
rm -rf "$TMP_SDK_DIR"

echo ""
echo "----------------------------------------------------------------"
echo "==> Build pipeline completed successfully."
echo "Artifacts available in: $(pwd)/$OUTPUT_DIR/"
echo "SDK Bundle: ${SDK_ZIP}"
ls -lh "$OUTPUT_DIR" | grep "FFI"
echo "----------------------------------------------------------------"
