#!/usr/bin/env bash
set -euo pipefail

SERVICE_ROOT="$(cd "$(dirname "$0")" && pwd)"
NATIVE_ROOT="$(cd "$SERVICE_ROOT/.." && pwd)"
REPO_ROOT="$(cd "$SERVICE_ROOT/../../../.." && pwd)"
OUTPUT="$(mktemp -d "${TMPDIR:-/tmp}/agent-native-rotation-evidence-tests.XXXXXX")"
VENDOR_SOURCE=""
cleanup() {
  [[ -z "$VENDOR_SOURCE" ]] || rm -rf "$VENDOR_SOURCE"
  rm -rf "$OUTPUT"
}
trap cleanup EXIT

ARCHITECTURES="${PRIVATE_VAULT_BUILD_ARCHITECTURES:-universal}"
if [[ "$ARCHITECTURES" != "universal" && "$ARCHITECTURES" != "arm64" ]]; then
  echo "Rotation evidence tests require universal or arm64" >&2
  exit 1
fi

FIXTURE="$OUTPUT/core-rotation-evidence.json"
(cd "$REPO_ROOT" && pnpm exec tsx \
  packages/core/scripts/materialize-rotation-evidence-native-fixture.ts \
  "$FIXTURE")

mkdir -p "$OUTPUT/vendor-tmp"
VENDOR_SOURCE="$(TMPDIR="$OUTPUT/vendor-tmp" \
  bash "$NATIVE_ROOT/fetch-private-vault-deps.sh")"
SDK="$(xcrun --sdk macosx --show-sdk-path)"

build_slice() {
  local architecture="$1"
  local host="$2"
  local sodium="$OUTPUT/libsodium-$architecture"
  mkdir -p "$sodium/build"
  (
    cd "$sodium/build"
    CC="$(xcrun -f clang)" \
    CFLAGS="-O2 -arch $architecture -mmacosx-version-min=13.0" \
    CPPFLAGS="-isysroot $SDK" \
    LDFLAGS="-arch $architecture -isysroot $SDK -mmacosx-version-min=13.0" \
      "$VENDOR_SOURCE/configure" --host="$host" --prefix="$sodium" \
        --disable-shared --enable-static --disable-dependency-tracking \
        >/dev/null
    make -j"$(sysctl -n hw.logicalcpu 2>/dev/null || echo 4)" >/dev/null
    make install >/dev/null
  )
  local binary="$OUTPUT/private-vault-rotation-evidence-tests-$architecture"
  xcrun clang -O1 -fobjc-arc -fblocks -Wall -Wextra -Werror \
    -isysroot "$SDK" -mmacosx-version-min=13.0 -arch "$architecture" \
    -I"$SERVICE_ROOT/crypto" -I"$SERVICE_ROOT/control" \
    -I"$sodium/include" -framework Foundation \
    "$SERVICE_ROOT/crypto/PrivateVaultCrypto.c" \
    "$SERVICE_ROOT/control/PrivateVaultAncCanonical.m" \
    "$SERVICE_ROOT/control/PrivateVaultRotationEvidence.m" \
    "$SERVICE_ROOT/control/PrivateVaultRotationEvidenceTests.m" \
    "$sodium/lib/libsodium.a" -o "$binary"
  lipo "$binary" -verify_arch "$architecture"
  ANC_ROTATION_EVIDENCE_FIXTURE_PATH="$FIXTURE" \
    ${architecture:+arch -"$architecture"} "$binary"
}

build_slice arm64 aarch64-apple-darwin
if [[ "$ARCHITECTURES" == "universal" ]]; then
  build_slice x86_64 x86_64-apple-darwin
fi

echo "Private Vault Core/native rotation evidence parity passed"
