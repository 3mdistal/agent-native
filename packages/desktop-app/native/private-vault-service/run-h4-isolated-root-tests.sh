#!/usr/bin/env bash
set -euo pipefail

DESKTOP_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SOURCE_ROOT="$DESKTOP_ROOT/native/private-vault-service"
OUTPUT="$(mktemp -d "${TMPDIR:-/tmp}/agent-native-private-vault-h4.XXXXXX")"
trap 'rm -rf "$OUTPUT"' EXIT
SDK="$(xcrun --sdk macosx --show-sdk-path)"
ARCHITECTURES="${PRIVATE_VAULT_BUILD_ARCHITECTURES:-arm64}"
if [[ "$ARCHITECTURES" != "arm64" && "$ARCHITECTURES" != "universal" ]]; then
  echo "H4 architectures must be arm64 or universal" >&2
  exit 1
fi

VENDOR_SOURCE="$(TMPDIR="$OUTPUT" bash "$DESKTOP_ROOT/native/fetch-private-vault-deps.sh")"

build_slice() {
  local architecture="$1" host="$2"
  local sodium_root="$OUTPUT/libsodium-$architecture"
  mkdir -p "$sodium_root/build"
  (
    cd "$sodium_root/build"
    CC="$(xcrun -f clang)" \
    CFLAGS="-O1 -arch $architecture -mmacosx-version-min=13.0" \
    CPPFLAGS="-isysroot $SDK" \
    LDFLAGS="-arch $architecture -isysroot $SDK -mmacosx-version-min=13.0" \
      "$VENDOR_SOURCE/configure" --host="$host" --prefix="$sodium_root" \
        --disable-shared --enable-static --disable-dependency-tracking >/dev/null
    make -j"$(sysctl -n hw.logicalcpu 2>/dev/null || echo 4)" >/dev/null
    make install >/dev/null
  )
  local executable="$OUTPUT/private-vault-h4-isolated-root-tests-$architecture"
  xcrun clang -O1 -fobjc-arc -fblocks -Wall -Wextra -Werror \
    -isysroot "$SDK" -arch "$architecture" -mmacosx-version-min=13.0 \
    -I"$SOURCE_ROOT/crypto" -I"$SOURCE_ROOT/control" \
    -I"$SOURCE_ROOT/storage" -I"$SOURCE_ROOT/transport" \
    -I"$SOURCE_ROOT/recovery" \
    -I"$sodium_root/include" \
    -DANC_PRIVATE_VAULT_TESTING=1 \
    -DANC_PRIVATE_VAULT_ENROLLMENT_AUTHORITY_LINKED=1 \
    -framework Foundation -framework Security -framework LocalAuthentication \
    "$SOURCE_ROOT/crypto/PrivateVaultCrypto.c" \
    "$SOURCE_ROOT/control/PrivateVaultAncCanonical.m" \
    "$SOURCE_ROOT/control/PrivateVaultControlLog.m" \
    "$SOURCE_ROOT/control/PrivateVaultControlLogInternal.m" \
    "$SOURCE_ROOT/control/PrivateVaultEnrollmentOffer.m" \
    "$SOURCE_ROOT/control/PrivateVaultEnrollmentChallenge.m" \
    "$SOURCE_ROOT/control/PrivateVaultEnrollmentAuthorizer.m" \
    "$SOURCE_ROOT/control/PrivateVaultEnrollmentAuthorization.m" \
    "$SOURCE_ROOT/control/PrivateVaultEnrollmentSasReceipt.m" \
    "$SOURCE_ROOT/control/PrivateVaultEekWrap.m" \
    "$SOURCE_ROOT/control/PrivateVaultGenesisBootstrap.m" \
    "$SOURCE_ROOT/control/PrivateVaultGenesisAuthorization.m" \
    "$SOURCE_ROOT/control/PrivateVaultGenesisAccountAdmission.m" \
    "$SOURCE_ROOT/control/PrivateVaultGenesisHostedAppend.m" \
    "$SOURCE_ROOT/control/PrivateVaultGenesisBuilder.m" \
    "$SOURCE_ROOT/control/PrivateVaultRecoveryWrap.m" \
    "$SOURCE_ROOT/control/PrivateVaultRecoveryAuthorization.m" \
    "$SOURCE_ROOT/control/PrivateVaultRecoveryBuilder.m" \
    "$SOURCE_ROOT/recovery/PrivateVaultRecoveryAuthority.m" \
    "$SOURCE_ROOT/storage/PrivateVaultKeychain.m" \
    "$SOURCE_ROOT/storage/PrivateVaultGuardedMemory.m" \
    "$SOURCE_ROOT/storage/PrivateVaultCustodyRecord.m" \
    "$SOURCE_ROOT/storage/PrivateVaultCustodyRepository.m" \
    "$SOURCE_ROOT/storage/PrivateVaultGenerationFence.m" \
    "$SOURCE_ROOT/storage/PrivateVaultRecoveryPreparationStore.m" \
    "$SOURCE_ROOT/storage/PrivateVaultAuthoritySnapshot.m" \
    "$SOURCE_ROOT/storage/PrivateVaultAuthorityStore.m" \
    "$SOURCE_ROOT/storage/PrivateVaultEnrollmentOfferArtifactStore.m" \
    "$SOURCE_ROOT/storage/PrivateVaultEnrollmentSasReceiptStore.m" \
    "$SOURCE_ROOT/storage/PrivateVaultEnrollmentCoordinator.m" \
    "$SOURCE_ROOT/transport/PrivateVaultBootstrapFrame.m" \
    "$SOURCE_ROOT/transport/PrivateVaultBootstrapReplay.m" \
    "$SOURCE_ROOT/tests/isolated-root-enrollment/PrivateVaultIsolatedRootEnrollmentTests.m" \
    "$sodium_root/lib/libsodium.a" -o "$executable"
  lipo "$executable" -verify_arch "$architecture"
  if [[ "$architecture" == "arm64" ]]; then "$executable"; else arch -x86_64 "$executable"; fi
}

build_slice arm64 aarch64-apple-darwin
if [[ "$ARCHITECTURES" == "universal" ]]; then
  build_slice x86_64 x86_64-apple-darwin
fi
