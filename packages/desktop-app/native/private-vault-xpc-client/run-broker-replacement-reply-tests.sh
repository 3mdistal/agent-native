#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
NODE_EXECUTABLE="${NODE_EXECUTABLE:-$(command -v node)}"
NODE_PREFIX="$(cd "$(dirname "$NODE_EXECUTABLE")/.." && pwd)"
NODE_HEADERS="${NODE_HEADERS:-$NODE_PREFIX/include/node}"
TEST_BINARY="$(mktemp "${TMPDIR:-/tmp}/agent-native-private-vault-broker-reply.XXXXXX")"

cleanup() {
  rm -f "$TEST_BINARY"
}
trap cleanup EXIT

xcrun clang++ -O1 -fblocks -std=c++20 -Wall -Wextra -Werror \
  -DNAPI_VERSION=8 \
  -DNODE_GYP_MODULE_NAME=private_vault_xpc_client \
  -I"$NODE_HEADERS" \
  -isysroot "$SDK" \
  -mmacosx-version-min=13.0 \
  -undefined dynamic_lookup \
  -framework Foundation \
  -framework AppKit \
  "$ROOT/BrokerReplacementReplyTests.mm" \
  -o "$TEST_BINARY"

"$TEST_BINARY"
