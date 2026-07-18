#!/usr/bin/env bash
set -eo pipefail

cd "$(dirname "$0")"

# Move to the root of the repository
cd ../

VERSION=$(grep '^version = ".*"' Cargo.toml | cut -d '"' -f 2)

# Delete old directory to ensure all files are updated
rm -rf crates/bitwarden-api-api/src

# Generate new API bindings
npx openapi-generator-cli generate \
    -i artifacts/api.json \
    -g rust \
    -o crates/bitwarden-api-api \
    --package-name bitwarden-api-api \
    -t ./support/openapi-template \
    --additional-properties=library=reqwest-trait,mockall,topLevelApiClient,supportMiddleware=true,packageVersion=$VERSION,packageDescription=\"API bindings for the Bitwarden API.\"

# The Nuri fork persists portable passkey extension state before the field exists in upstream
# bitwarden/server. Scheduled upstream regeneration must fail rather than silently erase it.
./support/verify-portable-passkey-bindings.sh \
    api \
    crates/bitwarden-api-api/src/models/cipher_fido2_credential_model.rs

npm run prettier
