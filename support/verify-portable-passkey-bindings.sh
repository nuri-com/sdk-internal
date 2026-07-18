#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <api|kotlin|swift> <generated-path>" >&2
  exit 2
}

require_file() {
  local file="$1"

  if [[ ! -f "$file" ]]; then
    echo "::error::Missing generated binding file: $file" >&2
    exit 1
  fi
}

require_literal() {
  local file="$1"
  local literal="$2"

  if ! grep -Fq -- "$literal" "$file"; then
    echo "::error::Generated binding contract is missing '$literal' in $file" >&2
    exit 1
  fi
}

require_literal_count() {
  local file="$1"
  local literal="$2"
  local minimum="$3"
  local count

  count="$(grep -Fc -- "$literal" "$file" || true)"
  if (( count < minimum )); then
    echo "::error::Generated binding contract expected at least $minimum occurrences of '$literal' in $file, found $count" >&2
    exit 1
  fi
}

reject_literal() {
  local file="$1"
  local literal="$2"

  if grep -Fq -- "$literal" "$file"; then
    echo "::error::Generated binding contract exposes forbidden plaintext extension state '$literal' in $file" >&2
    exit 1
  fi
}

verify_no_decoded_extension_state() {
  local vault_file="$1"
  local fido_file="$2"

  for literal in \
    Fido2ExtensionStateView \
    uvHmacSeed \
    nonUvHmacSeed \
    uv_hmac_seed \
    non_uv_hmac_seed; do
    reject_literal "$vault_file" "$literal"
    reject_literal "$fido_file" "$literal"
  done
}

binding_type="${1:-}"
generated_path="${2:-}"

if [[ -z "$binding_type" || -z "$generated_path" ]]; then
  usage
fi

case "$binding_type" in
  api)
    require_file "$generated_path"
    require_literal "$generated_path" 'rename = "extensionState"'
    require_literal "$generated_path" 'pub extension_state: Option<String>,'
    require_literal "$generated_path" 'skip_serializing_if = "Option::is_none"'
    reject_literal "$generated_path" 'uv_hmac_seed'
    reject_literal "$generated_path" 'non_uv_hmac_seed'
    ;;
  kotlin)
    vault_file="$generated_path/com/bitwarden/vault/bitwarden_vault.kt"
    fido_file="$generated_path/com/bitwarden/fido/bitwarden_fido.kt"
    require_file "$vault_file"
    require_file "$fido_file"
    require_literal "$vault_file" 'data class Fido2Credential ('
    require_literal "$vault_file" 'data class Fido2CredentialView ('
    require_literal_count "$vault_file" 'val `extensionState`: EncString?' 2
    require_literal "$fido_file" 'data class ClientExtensionResults ('
    require_literal "$fido_file" 'val `prf`: ClientPrfOutput?'
    require_literal "$fido_file" 'data class ClientPrfOutput ('
    require_literal "$fido_file" 'val `enabled`: kotlin.Boolean?'
    require_literal "$fido_file" 'val `results`: PrfOutputValues?'
    require_literal "$fido_file" 'data class PrfOutputValues ('
    require_literal "$fido_file" 'val `first`: kotlin.ByteArray'
    require_literal "$fido_file" 'val `second`: kotlin.ByteArray?'
    require_literal "$fido_file" 'val `alreadyHashed`: kotlin.Boolean'
    verify_no_decoded_extension_state "$vault_file" "$fido_file"
    ;;
  swift)
    vault_file="$generated_path/BitwardenVault.swift"
    fido_file="$generated_path/BitwardenFido.swift"
    require_file "$vault_file"
    require_file "$fido_file"
    require_literal "$vault_file" 'public struct Fido2Credential:'
    require_literal "$vault_file" 'public struct Fido2CredentialView:'
    require_literal_count "$vault_file" 'public let extensionState: EncString?' 2
    require_literal "$fido_file" 'public struct ClientExtensionResults:'
    require_literal "$fido_file" 'public let prf: ClientPrfOutput?'
    require_literal "$fido_file" 'public struct ClientPrfOutput:'
    require_literal "$fido_file" 'public let enabled: Bool?'
    require_literal "$fido_file" 'public let results: PrfOutputValues?'
    require_literal "$fido_file" 'public struct PrfOutputValues:'
    require_literal "$fido_file" 'public let first: Data'
    require_literal "$fido_file" 'public let second: Data?'
    require_literal "$fido_file" 'public let alreadyHashed: Bool'
    verify_no_decoded_extension_state "$vault_file" "$fido_file"
    ;;
  *)
    usage
    ;;
esac

echo "Verified portable passkey contract in generated $binding_type bindings."
