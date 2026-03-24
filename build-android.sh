#!/bin/bash
# build-android.sh — Build and deploy Android FFI libraries

echo "----------------------------------------------------------------"
echo "        HiVoid Android Shared Library Builder (FFI)"
echo "----------------------------------------------------------------"

read -p "Enter build version (default: dev): " VERSION
VERSION=${VERSION:-dev}
echo "==> Target Version: ${VERSION}"

mkdir -p dist

if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running."
    exit 1
fi

echo "==> Compiling Android libraries inside Docker..."
docker buildx build --platform linux/amd64 \
    --build-arg VERSION="${VERSION}" \
    -f Dockerfile.android \
    --output type=local,dest=./dist \
    .

if [ $? -ne 0 ]; then
    echo "ERROR: Docker build failed."
    exit 1
fi

# ── Copy .so files to Android jniLibs ─────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$(cd "${SCRIPT_DIR}/../HiVoid-App" 2>/dev/null && pwd)"

# FIX: Removed incorrect JNILIBS definition
JNILIBS="${APP_DIR}/android/app/src/main/jniLibs"

echo "==> Copying .so files to jniLibs..."
if [ -d "${JNILIBS}" ]; then
    # FIX: Copy all ABIs for full compatibility
    for ABI in arm64-v8a x86_64 armeabi-v7a x86; do
        SRC="dist/android/${ABI}/libhivoid.so"
        DST_DIR="${JNILIBS}/${ABI}"
        DST="${DST_DIR}/libhivoid.so"
        if [ -f "${SRC}" ]; then
            mkdir -p "${DST_DIR}"
            cp "${SRC}" "${DST}"
            echo "  -> Copied: ${DST}"
        else
            echo "  !! Missing: ${SRC}"
        fi
    done
    echo "==> jniLibs updated successfully."
else
    echo "WARNING: jniLibs not found at: ${JNILIBS}"
    echo "  Manually copy dist/android/<ABI>/libhivoid.so to your jniLibs folder."
fi

echo "----------------------------------------------------------------"
echo "Build complete!"
echo "  SDK zips: ./dist/hivoid-android-sdk-*-${VERSION}.zip"
echo "  Libs:     ./dist/android/"
echo "----------------------------------------------------------------"