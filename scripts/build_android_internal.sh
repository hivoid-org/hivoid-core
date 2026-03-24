#!/bin/bash
# scripts/build_android_internal.sh

set -e

mkdir -p dist/android

ARCHS=(
    "arm64:arm64-v8a:aarch64-linux-android:34"
    "amd64:x86_64:x86_64-linux-android:34"
    "arm:armeabi-v7a:armv7a-linux-androideabi:34"
    "386:x86:i686-linux-android:34"
)

for entry in "${ARCHS[@]}"; do
    IFS=":" read -r GOARCH ABI_DIR PREFIX API_LEVEL <<< "$entry"

    OUT_DIR="dist/android/${ABI_DIR}"
    mkdir -p "${OUT_DIR}"

    echo "==> Building Android FFI: GOARCH=${GOARCH} ABI=${ABI_DIR} API=${API_LEVEL}"

    # FIX: Correct toolchain path for NDK r26+
    # Binary name format: {PREFIX}{API_LEVEL}-clang
    # Example: aarch64-linux-android34-clang
    TOOLCHAIN="${NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin"
    CC_BIN="${TOOLCHAIN}/${PREFIX}${API_LEVEL}-clang"
    CXX_BIN="${TOOLCHAIN}/${PREFIX}${API_LEVEL}-clang++"

    if [ ! -f "${CC_BIN}" ]; then
        echo "ERROR: Compiler not found: ${CC_BIN}"
        echo "  Available compilers for ${PREFIX}:"
        ls "${TOOLCHAIN}/${PREFIX}"* 2>/dev/null || echo "  (none found)"
        exit 1
    fi

    export CGO_ENABLED=1
    export GOOS=android
    export GOARCH=${GOARCH}
    export CC="${CC_BIN}"
    export CXX="${CXX_BIN}"
    # FIX: Use AR from NDK instead of system default
    export AR="${TOOLCHAIN}/llvm-ar"

    go build -buildmode=c-shared \
        -ldflags "-X main.Version=${VERSION} -s -w" \
        -o "${OUT_DIR}/libhivoid.so" \
        ./ffi

    echo "  -> ${OUT_DIR}/libhivoid.so ($(du -sh "${OUT_DIR}/libhivoid.so" | cut -f1))"
done

# Bundle each ABI separately
cd dist/android
for ABI in *; do
    if [ -d "$ABI" ]; then
        zip -r "../../dist/hivoid-android-sdk-${ABI}-${VERSION}.zip" "$ABI"
    fi
done
cd ../..

echo "==> All Android builds and individual zips are ready."