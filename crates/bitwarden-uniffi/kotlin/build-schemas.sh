#!/usr/bin/env bash
set -eo pipefail

cd "$(dirname "$0")"

SDK_REPO_ROOT="$(git rev-parse --show-toplevel)"
GENERATED_DIR="sdk/src/main/java"

# UniFFI does not remove source files for modules that disappear. Clear only the ignored generated
# source tree so every SDK build reflects the current native library exactly.
rm -rf "$GENERATED_DIR"

cargo run -p uniffi-bindgen generate \
  ./sdk/src/main/jniLibs/arm64-v8a/libbitwarden_uniffi.so \
  --language kotlin \
  --no-format \
  --out-dir sdk/src/main/java

"$SDK_REPO_ROOT/support/verify-portable-passkey-bindings.sh" kotlin sdk/src/main/java
