#!/bin/bash
# scripts/build_android_internal.sh

set -e

mkdir -p dist/android

# FIX: API level رو 34 کردیم (مطابق emulator و دستگاه‌های مدرن)
# فرمت: GOARCH:ABI_DIR:COMPILER_PREFIX:API_LEVEL
#
# FIX: armeabi-v7a و x86 (32-bit) حذف شدن:
#   - API 34 emulator فقط x86_64 است
#   - دستگاه‌های واقعی جدید فقط arm64-v8a دارن
#   - اگه نیاز به 32-bit داری، دو خط آخر رو uncomment کن
ARCHS=(
    "arm64:arm64-v8a:aarch64-linux-android:34"
    "amd64:x86_64:x86_64-linux-android:34"
    # "arm:armeabi-v7a:armv7a-linux-androideabi:24"   # فقط برای دستگاه‌های قدیمی
    # "386:x86:i686-linux-android:24"                 # فقط برای emulator قدیمی
)

for entry in "${ARCHS[@]}"; do
    IFS=":" read -r GOARCH ABI_DIR PREFIX API_LEVEL <<< "$entry"

    OUT_DIR="dist/android/${ABI_DIR}"
    mkdir -p "${OUT_DIR}"

    echo "==> Building Android FFI: GOARCH=${GOARCH} ABI=${ABI_DIR} API=${API_LEVEL}"

    # FIX: مسیر صحیح toolchain در NDK r26+
    # شکل اسم binary: {PREFIX}{API_LEVEL}-clang
    # مثال: aarch64-linux-android34-clang
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
    # FIX: AR هم باید از NDK باشه، نه system default
    export AR="${TOOLCHAIN}/llvm-ar"

    go build -buildmode=c-shared \
        -ldflags "-X main.Version=${VERSION} -s -w" \
        -o "${OUT_DIR}/libhivoid.so" \
        ./ffi

    echo "  -> ${OUT_DIR}/libhivoid.so ($(du -sh "${OUT_DIR}/libhivoid.so" | cut -f1))"
done

# Bundle
cd dist
zip -r "hivoid-android-sdk-${VERSION}.zip" android/
cd ..

echo "==> All Android builds done."