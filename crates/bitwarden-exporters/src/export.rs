use bitwarden_collections::collection::Collection;
use bitwarden_core::{Client, OrganizationId, key_management::KeySlotIds};
use bitwarden_crypto::{CompositeEncryptable, IdentifyKey, KeyStoreContext};
use bitwarden_vault::{Cipher, CipherView, Folder, FolderView};

use crate::{
    ExportError, ExportFormat, ImportingCipher,
    csv::export_csv,
    cxf::{Account, build_cxf, parse_cxf},
    encrypted_json::export_encrypted_json,
    json::export_json,
};

pub(crate) async fn export_vault(
    client: &Client,
    folders: Vec<Folder>,
    ciphers: Vec<Cipher>,
    format: ExportFormat,
) -> Result<String, ExportError> {
    let key_store = client.internal.get_key_store();

    let folders: Vec<FolderView> = key_store.decrypt_list(&folders)?;
    let folders: Vec<crate::Folder> = folders.into_iter().flat_map(|f| f.try_into()).collect();

    let ciphers: Vec<crate::Cipher> = ciphers
        .into_iter()
        .flat_map(|c| crate::Cipher::from_cipher(key_store, c))
        .collect();

    match format {
        ExportFormat::Csv => Ok(export_csv(folders, ciphers)?),
        ExportFormat::Json => Ok(export_json(folders, ciphers)?),
        ExportFormat::EncryptedJson { password } => Ok(export_encrypted_json(
            folders,
            ciphers,
            password,
            client.internal.get_kdf().await?,
        )?),
    }
}

pub(crate) fn export_organization_vault(
    _collections: Vec<Collection>,
    _ciphers: Vec<Cipher>,
    _format: ExportFormat,
) -> Result<String, ExportError> {
    todo!();
}

/// See [crate::ExporterClient::export_cxf] for more documentation.
pub(crate) fn export_cxf(
    client: &Client,
    account: Account,
    ciphers: Vec<Cipher>,
) -> Result<String, ExportError> {
    let key_store = client.internal.get_key_store();

    let mut ciphers: Vec<crate::Cipher> = ciphers
        .into_iter()
        .flat_map(|c| crate::Cipher::from_cipher(key_store, c))
        .collect();

    for cipher in &mut ciphers {
        if let crate::CipherType::Login(login) = &mut cipher.r#type {
            login.sanitize_uris();
        }
    }

    Ok(build_cxf(account, ciphers)?)
}

/// Encrypts a parsed/imported cipher for the user's vault, or for an organization when
/// `organization_id` is set. Shared by the importers (`import_kdbx`) and by CXF import; lives here
/// alongside the `ImportingCipher` interchange model and the `From<ImportingCipher> for CipherView`
/// bridge.
pub fn encrypt_import(
    ctx: &mut KeyStoreContext<KeySlotIds>,
    mut cipher: ImportingCipher,
    organization_id: Option<OrganizationId>,
) -> Result<Cipher, ExportError> {
    // Move passkeys out before converting the rest of the import model. The conversion
    // intentionally omits FIDO2 credentials because they require composite encryption.
    let passkeys = match &mut cipher.r#type {
        crate::CipherType::Login(login) => login.fido2_credentials.take(),
        _ => None,
    };

    let mut view: CipherView = cipher.into();
    view.organization_id = organization_id;

    if let Some(passkeys) = passkeys {
        let passkeys = passkeys.into_iter().map(|p| p.into()).collect();

        view.set_new_fido2_credentials(ctx, passkeys)?;
    }

    let new_cipher = view.encrypt_composite(ctx, view.key_identifier())?;

    Ok(new_cipher)
}

/// See [crate::ExporterClient::import_cxf] for more documentation.
pub(crate) fn import_cxf(client: &Client, payload: String) -> Result<Vec<Cipher>, ExportError> {
    let key_store = client.internal.get_key_store();
    let mut ctx = key_store.context();

    let ciphers = parse_cxf(payload)?;
    let ciphers: Result<Vec<Cipher>, _> = ciphers
        .into_iter()
        .map(|c| encrypt_import(&mut ctx, c, None))
        .collect();

    ciphers
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use bitwarden_vault::Fido2ExtensionStateView;
    use chrono::{TimeZone, Utc};
    use zeroize::Zeroizing;

    use super::*;

    #[test]
    fn encrypt_import_round_trips_moved_passkey_secret_state() {
        let creation_date = Utc.with_ymd_and_hms(2026, 7, 18, 12, 0, 0).unwrap();
        let extension_state = Fido2ExtensionStateView {
            prf_hmac_algorithm: "hmac-secret".to_string(),
            uv_hmac_seed: "uv-seed-sentinel".to_string(),
            non_uv_hmac_seed: Some("non-uv-seed-sentinel".to_string()),
            cred_blob: Some("credential-blob-sentinel".to_string()),
            large_blob: Some("large-blob-sentinel".to_string()),
            key_algorithm_metadata: "ES256".to_string(),
        };
        let importing_cipher = ImportingCipher {
            folder_id: None,
            name: "Portable passkey".to_string(),
            notes: None,
            r#type: crate::CipherType::Login(Box::new(crate::Login {
                username: Some("test@example.com".to_string()),
                password: Some("login-password".to_string()),
                login_uris: vec![],
                totp: None,
                fido2_credentials: Some(vec![crate::Fido2Credential {
                    credential_id: "credential-id".to_string(),
                    key_type: "public-key".to_string(),
                    key_algorithm: "ECDSA".to_string(),
                    key_curve: "P-256".to_string(),
                    key_value: "private-key-sentinel".to_string(),
                    rp_id: "example.com".to_string(),
                    user_handle: Some("user-handle".to_string()),
                    user_name: Some("test@example.com".to_string()),
                    counter: 7,
                    rp_name: Some("Example".to_string()),
                    user_display_name: Some("Test User".to_string()),
                    discoverable: "true".to_string(),
                    creation_date,
                    extension_state: Some(serde_json::to_string(&extension_state).unwrap()),
                }]),
            })),
            favorite: false,
            reprompt: 0,
            fields: vec![],
            revision_date: creation_date,
            creation_date,
            deleted_date: None,
        };
        let key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let key_store = create_test_crypto_with_user_key(key);

        let encrypted = encrypt_import(&mut key_store.context(), importing_cipher, None).unwrap();
        let view: CipherView = key_store.decrypt(&encrypted).unwrap();

        assert_eq!(view.name, "Portable passkey");
        assert_eq!(
            view.login
                .as_ref()
                .and_then(|login| login.password.as_deref()),
            Some("login-password")
        );

        let credentials = Zeroizing::new(
            view.get_fido2_credentials(&mut key_store.context())
                .unwrap(),
        );
        let credential = credentials.first().unwrap();
        assert_eq!(credential.key_value, "private-key-sentinel");
        assert_eq!(credential.counter, "7");
        assert_eq!(credential.extension_state.as_ref(), Some(&extension_state));
    }
}
