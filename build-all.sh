#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e
# Exit on pipeline failure
set -o pipefail

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}==>${NC} Verifying Docker capability..."
if ! command -v docker >/dev/null 2>&1; then
    echo -e "${RED}Error: docker is not installed or not in PATH.${NC}"
    exit 1
fi

if ! docker buildx version >/dev/null 2>&1; then
    echo -e "${RED}Error: docker buildx is not available. Please install a newer version of Docker.${NC}"
    exit 1
fi

# Ensure an active Buildx builder is present
BUILDER_NAME="hivoid-cross-builder"
echo -e "${BLUE}==>${NC} Ensuring Buildx builder instance '${BUILDER_NAME}' exists..."
if ! docker buildx ls | grep -qw "$BUILDER_NAME"; then
    echo "Creating new builder instance..."
    docker buildx create --name "$BUILDER_NAME" --use
else
    echo "Using existing builder instance..."
    docker buildx use "$BUILDER_NAME"
fi

# Guarantee local output directory is prepped
mkdir -p ./dist

echo -e "${BLUE}==>${NC} Starting parallel cross-platform build pipeline via Docker Buildx..."
echo "This will compile Linux, Windows static artifacts."

# Run docker buildx and extract output to ./dist
# We use --output type=local,dest=./dist to drop artifacts straight into host folder
# We specify --target artifacts to stop after the final stage
docker buildx build \
    --builder "$BUILDER_NAME" \
    --target artifacts \
    --output type=local,dest=./dist \
    --file Dockerfile \
    .

echo -e "\n${GREEN}==>${NC} Build pipeline completed successfully."
echo "Binaries have been extracted to $(pwd)/dist/"
echo "Artifacts generated:"
ls -lh ./dist/
