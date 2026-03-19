#!/usr/bin/env bash
# HiVoid FFI Internal Build Script (runs within Docker)
# Optimized for Go + CGo cross-compilation

set -e

# Target directory
DIST_DIR="/dist"
mkdir -p "${DIST_DIR}"

# Build variables
LDFLAGS="-s -w"
SRC="./ffi/hivoid_ffi.go"
API_LEVEL=${API_LEVEL:-35}
VERSION=${VERSION:-dev}

echo "Starting HiVoid FFI Cross-Platform Build Pipeline (${VERSION})..."

build_target() {
    local OS=$1
    local ARCH=$2
    local COMPILER=$3
    local EXT=$4
    local ROLE="FFI"
    local BASE_NAME="hivoid-core-${OS}-${ARCH}-${ROLE}-${VERSION}"
    local BIN_NAME="hivoid-${OS}-${ARCH}${EXT}"
    local ZIP_NAME="${BASE_NAME}.zip"
    
    echo "----------------------------------------------------------------"
    echo "Building: ${OUTPUT_NAME}"
    echo "Compiler: ${COMPILER}"
    
    # Run Go build
    GOOS=${OS} GOARCH=${ARCH} CGO_ENABLED=1 CC=${COMPILER} \
    go build -buildmode=c-shared -ldflags "${LDFLAGS}" -o "/tmp/${BIN_NAME}" "${SRC}"
    
    # Zip the artifact (matching standard Dockerfile behavior)
    zip -j "${DIST_DIR}/${ZIP_NAME}" "/tmp/${BIN_NAME}"
    
    # Cleanup
    rm -f "/tmp/${BIN_NAME}"
    rm -f "/tmp/hivoid-${OS}-${ARCH}.h" # cleanup cgo header
}

# ── Linux (Shared Objects) ───────────────────────────────────────────────────
# x64
build_target linux amd64 "gcc" ".so"
# x86 (32-bit)
# uses gcc-multilib with -m32 flag
build_target linux 386 "gcc -m32" ".so"

# ── Windows (Dynamic Link Libraries) ──────────────────────────────────────────
# x64
build_target windows amd64 "x86_64-w64-mingw32-gcc" ".dll"
# x86 (32-bit)
build_target windows 386 "i686-w64-mingw32-gcc" ".dll"

# ── Android (Shared Objects) ──────────────────────────────────────────────────
# ARM64 (v8-a)
build_target android arm64 "aarch64-linux-android${API_LEVEL}-clang" ".so"
# ARMv7 (v7-a)
build_target android arm "armv7a-linux-androideabi${API_LEVEL}-clang" ".so"
# x86_64
build_target android amd64 "x86_64-linux-android${API_LEVEL}-clang" ".so"
# x86 (32-bit)
build_target android 386 "i686-linux-android${API_LEVEL}-clang" ".so"

echo "----------------------------------------------------------------"
echo "Build pipeline completed successfully."
ls -lh "${DIST_DIR}"
