#![doc = include_str!("../README.md")]

use bitwarden_core::key_management::KeySlotIds;
use bitwarden_crypto::KeyStoreContext;
use bitwarden_encoding::{B64Url, NotB64UrlEncodedError};
use bitwarden_vault::{
    CipherError, CipherView, Fido2CredentialFullView, Fido2CredentialNewView, Fido2CredentialView,
    Fido2ExtensionStateView,
};
use crypto::{CoseKeyToPkcs8Error, PrivateKeyFromSecretKeyError};
use passkey::types::{CredentialExtensions, Passkey, StoredHmacSecret, ctap2::Aaguid};

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod authenticator;
mod client;
mod client_fido;
mod crypto;
mod device_auth_key;
mod traits;
mod types;
pub use authenticator::{
    CredentialsForAutofillError, Fido2Authenticator, GetAssertionError, MakeCredentialError,
    SilentlyDiscoverCredentialsError,
};
pub use client::{Fido2Client, Fido2ClientError};
pub use client_fido::{ClientFido2, ClientFido2Ext, DecryptFido2AutofillCredentialsError};
pub use device_auth_key::{
    DeviceAuthKeyAuthenticator, DeviceAuthKeyError, DeviceAuthKeyGetAssertionResult,
    DeviceAuthKeyMetadata, DeviceAuthKeyRecord, DeviceAuthKeyStore,
};
pub use passkey::authenticator::UiHint;
use thiserror::Error;
pub use traits::{
    CheckUserOptions, CheckUserResult, Fido2CallbackError, Fido2CredentialStore,
    Fido2UserInterface, Verification,
};
pub use types::{
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, ClientData,
    Fido2CredentialAutofillView, Fido2CredentialAutofillViewError, GetAssertionExtensionsInput,
    GetAssertionExtensionsOutput, GetAssertionPrfInput, GetAssertionPrfOutput, GetAssertionRequest,
    GetAssertionResult, MakeCredentialExtensionsInput, MakeCredentialExtensionsOutput,
    MakeCredentialPrfInput, MakeCredentialPrfOutput, MakeCredentialRequest, MakeCredentialResult,
    Options, Origin, PrfInputValues, PrfOutputValues,
    PublicKeyCredentialAuthenticatorAssertionResponse,
    PublicKeyCredentialAuthenticatorAttestationResponse, PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity, UnverifiedAssetLink,
};

use self::crypto::{cose_key_to_pkcs8, pkcs8_to_cose_key};

// This is the AAGUID for the Bitwarden Passkey provider (d548826e-79b4-db40-a3d8-11116f7e8349)
// It is used for the Relaying Parties to identify the authenticator during registration
const AAGUID: Aaguid = Aaguid([
    0xd5, 0x48, 0x82, 0x6e, 0x79, 0xb4, 0xdb, 0x40, 0xa3, 0xd8, 0x11, 0x11, 0x6f, 0x7e, 0x83, 0x49,
]);

#[allow(dead_code, missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SelectedCredential {
    cipher: CipherView,
    credential: Fido2CredentialView,
}

// This container is needed so we can properly implement the TryFrom trait for Passkey
// Otherwise we need to decrypt the Fido2 credentials every time we create a CipherView
#[derive(Clone)]
pub(crate) struct CipherViewContainer {
    cipher: CipherView,
    fido2_credentials: Vec<Fido2CredentialFullView>,
}

impl CipherViewContainer {
    fn new(cipher: CipherView, ctx: &mut KeyStoreContext<KeySlotIds>) -> Result<Self, CipherError> {
        let fido2_credentials = cipher.get_fido2_credentials(ctx)?;
        Ok(Self {
            cipher,
            fido2_credentials,
        })
    }
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum Fido2Error {
    #[error(transparent)]
    Decode(#[from] NotB64UrlEncodedError),

    #[error(transparent)]
    UnknownEnum(#[from] UnknownEnumError),

    #[error(transparent)]
    InvalidGuid(#[from] InvalidGuidError),

    #[error(transparent)]
    PrivateKeyFromSecretKey(#[from] PrivateKeyFromSecretKeyError),

    #[error("No Fido2 credentials found")]
    NoFido2CredentialsFound,

    #[error("Invalid counter")]
    InvalidCounter,

    #[error("Unsupported PRF/HMAC algorithm: {0}")]
    UnsupportedHmacAlgorithm(String),

    #[error("Invalid {field} HMAC seed length: expected 32 bytes, got {actual}")]
    InvalidHmacSeedLength { field: &'static str, actual: usize },
}

impl TryFrom<CipherViewContainer> for Passkey {
    type Error = Fido2Error;

    fn try_from(value: CipherViewContainer) -> Result<Self, Self::Error> {
        let cred = value
            .fido2_credentials
            .first()
            .ok_or(Fido2Error::NoFido2CredentialsFound)?;

        try_from_credential_full_view(cred.clone())
    }
}

const HMAC_SEED_LENGTH: usize = 32;

fn decode_hmac_seed(field: &'static str, value: &str) -> Result<Vec<u8>, Fido2Error> {
    let seed = B64Url::try_from(value)?.into_bytes();
    if seed.len() != HMAC_SEED_LENGTH {
        return Err(Fido2Error::InvalidHmacSeedLength {
            field,
            actual: seed.len(),
        });
    }
    Ok(seed)
}

pub(crate) fn stored_hmac_secret_from_extension_state(
    extension_state: Option<&Fido2ExtensionStateView>,
) -> Result<Option<StoredHmacSecret>, Fido2Error> {
    let Some(extension_state) = extension_state else {
        return Ok(None);
    };

    if extension_state.prf_hmac_algorithm != "hmac-secret" {
        return Err(Fido2Error::UnsupportedHmacAlgorithm(
            extension_state.prf_hmac_algorithm.clone(),
        ));
    }

    let cred_with_uv = decode_hmac_seed("UV", &extension_state.uv_hmac_seed)?;
    let cred_without_uv = extension_state
        .non_uv_hmac_seed
        .as_deref()
        .map(|seed| decode_hmac_seed("non-UV", seed))
        .transpose()?;

    Ok(Some(StoredHmacSecret {
        cred_with_uv,
        cred_without_uv,
    }))
}

fn try_from_credential_full_view(value: Fido2CredentialFullView) -> Result<Passkey, Fido2Error> {
    let counter: u32 = value
        .counter
        .parse()
        .map_err(|_| Fido2Error::InvalidCounter)?;
    let counter = (counter != 0).then_some(counter);
    let key_value = B64Url::try_from(value.key_value)?;
    let user_handle = value.user_handle.map(B64Url::try_from).transpose()?;

    let key = pkcs8_to_cose_key(key_value.as_bytes())?;

    let hmac_secret = stored_hmac_secret_from_extension_state(value.extension_state.as_ref())?;

    Ok(Passkey {
        key,
        credential_id: string_to_guid_bytes(&value.credential_id)?.into(),
        rp_id: value.rp_id.clone(),
        user_handle: user_handle.map(|u| u.into_bytes().into()),
        counter,
        extensions: CredentialExtensions { hmac_secret },
    })
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum FillCredentialError {
    #[error(transparent)]
    InvalidInputLength(#[from] InvalidInputLengthError),
    #[error(transparent)]
    CoseKeyToPkcs8(#[from] CoseKeyToPkcs8Error),
    #[error("{0}")]
    UnsupportedAlgorithm(String),
    #[error("Invalid {field} HMAC seed length: expected 32 bytes, got {actual}")]
    InvalidHmacSeedLength { field: &'static str, actual: usize },
    #[error("Existing extension state is present but the passkey has no HMAC secret")]
    MissingHmacSecret,
}

fn extension_state_from_hmac_secret(
    hmac_secret: Option<&StoredHmacSecret>,
    existing: Option<&Fido2ExtensionStateView>,
) -> Result<Option<Fido2ExtensionStateView>, FillCredentialError> {
    let Some(hmac_secret) = hmac_secret else {
        return if existing.is_some() {
            Err(FillCredentialError::MissingHmacSecret)
        } else {
            Ok(None)
        };
    };

    for (field, seed) in [
        ("UV", Some(hmac_secret.cred_with_uv.as_slice())),
        (
            "non-UV",
            hmac_secret.cred_without_uv.as_ref().map(Vec::as_slice),
        ),
    ] {
        if let Some(seed) = seed
            && seed.len() != HMAC_SEED_LENGTH
        {
            return Err(FillCredentialError::InvalidHmacSeedLength {
                field,
                actual: seed.len(),
            });
        }
    }

    Ok(Some(Fido2ExtensionStateView {
        prf_hmac_algorithm: existing
            .map(|state| state.prf_hmac_algorithm.clone())
            .unwrap_or_else(|| "hmac-secret".to_string()),
        uv_hmac_seed: B64Url::from(hmac_secret.cred_with_uv.clone()).to_string(),
        non_uv_hmac_seed: hmac_secret
            .cred_without_uv
            .as_ref()
            .map(|seed| B64Url::from(seed.clone()).to_string()),
        cred_blob: existing.and_then(|state| state.cred_blob.clone()),
        large_blob: existing.and_then(|state| state.large_blob.clone()),
        key_algorithm_metadata: existing
            .map(|state| state.key_algorithm_metadata.clone())
            .unwrap_or_else(|| "ES256".to_string()),
    }))
}

pub(crate) fn fill_with_credential_preserving_extension_state(
    view: &Fido2CredentialView,
    value: Passkey,
    existing_extension_state: Option<&Fido2ExtensionStateView>,
) -> Result<Fido2CredentialFullView, FillCredentialError> {
    let cred_id: Vec<u8> = value.credential_id.into();
    let user_handle = value
        .user_handle
        .map(|u| B64Url::from(u.to_vec()).to_string());
    let key_value = B64Url::from(cose_key_to_pkcs8(&value.key)?).to_string();

    // Derive key algorithm and curve from the COSE key instead of hardcoding ECDSA/P-256.
    let (key_algorithm, key_curve) = derive_algorithm_from_cose_key(&value.key)?;

    let extension_state = extension_state_from_hmac_secret(
        value.extensions.hmac_secret.as_ref(),
        existing_extension_state,
    )?;

    Ok(Fido2CredentialFullView {
        credential_id: guid_bytes_to_string(&cred_id)?,
        key_type: "public-key".to_owned(),
        key_algorithm,
        key_curve,
        key_value,
        rp_id: value.rp_id,
        rp_name: view.rp_name.clone(),
        user_handle,

        counter: value.counter.unwrap_or(0).to_string(),
        user_name: view.user_name.clone(),
        user_display_name: view.user_display_name.clone(),
        discoverable: "true".to_owned(),
        creation_date: chrono::offset::Utc::now(),
        extension_state,
    })
}

#[allow(missing_docs)]
pub fn fill_with_credential(
    view: &Fido2CredentialView,
    value: Passkey,
) -> Result<Fido2CredentialFullView, FillCredentialError> {
    fill_with_credential_preserving_extension_state(view, value, None)
}

/// Derive the key algorithm and curve name from a COSE key.
///
/// Returns `(algorithm_name, curve_name)` or an error for unsupported algorithms.
/// This validates the imported signing-key algorithm instead of silently hardcoding ECDSA P-256.
fn derive_algorithm_from_cose_key(
    key: &coset::CoseKey,
) -> Result<(String, String), FillCredentialError> {
    use coset::{Label, RegisteredLabel, RegisteredLabelWithPrivate, iana::EnumI64};

    match &key.kty {
        RegisteredLabel::Assigned(coset::iana::KeyType::EC2) => {}
        other => {
            return Err(FillCredentialError::UnsupportedAlgorithm(format!(
                "unsupported COSE key type: {other:?}, expected EC2"
            )));
        }
    }

    match key.alg.as_ref() {
        Some(RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::ES256)) => {}
        Some(other) => {
            return Err(FillCredentialError::UnsupportedAlgorithm(format!(
                "unsupported COSE algorithm: {other:?}, expected ES256"
            )));
        }
        None => {
            return Err(FillCredentialError::UnsupportedAlgorithm(
                "missing COSE algorithm, expected ES256".to_string(),
            ));
        }
    }

    let curve = key
        .params
        .iter()
        .find_map(|(label, value)| {
            if label == &Label::Int(-1) {
                value
                    .as_integer()
                    .and_then(|value| i64::try_from(i128::from(value)).ok())
            } else {
                None
            }
        })
        .ok_or_else(|| {
            FillCredentialError::UnsupportedAlgorithm(
                "missing COSE EC2 curve, expected P-256".to_string(),
            )
        })?;

    if curve != coset::iana::EllipticCurve::P_256.to_i64() {
        return Err(FillCredentialError::UnsupportedAlgorithm(format!(
            "unsupported COSE EC2 curve: {curve}, expected P-256"
        )));
    }

    Ok(("ECDSA".to_string(), "P-256".to_string()))
}

pub(crate) fn try_from_credential_new_view(
    user: &passkey::types::ctap2::make_credential::PublicKeyCredentialUserEntity,
    rp: &passkey::types::ctap2::make_credential::PublicKeyCredentialRpEntity,
) -> Result<Fido2CredentialNewView, InvalidInputLengthError> {
    let cred_id: Vec<u8> = vec![0; 16];
    let user_handle = B64Url::from(user.id.to_vec()).to_string();

    Ok(Fido2CredentialNewView {
        // TODO: Why do we have a credential id here?
        credential_id: guid_bytes_to_string(&cred_id)?,
        key_type: "public-key".to_owned(),
        key_algorithm: "ECDSA".to_owned(),
        key_curve: "P-256".to_owned(),
        rp_id: rp.id.clone(),
        rp_name: rp.name.clone(),
        user_handle: Some(user_handle),

        counter: 0.to_string(),
        user_name: user.name.clone(),
        user_display_name: user.display_name.clone(),
        creation_date: chrono::offset::Utc::now(),
    })
}

pub(crate) fn try_from_credential_full(
    value: Passkey,
    user: passkey::types::ctap2::make_credential::PublicKeyCredentialUserEntity,
    rp: passkey::types::ctap2::make_credential::PublicKeyCredentialRpEntity,
    options: passkey::types::ctap2::get_assertion::Options,
) -> Result<Fido2CredentialFullView, FillCredentialError> {
    let cred_id: Vec<u8> = value.credential_id.into();
    let key_value = B64Url::from(cose_key_to_pkcs8(&value.key)?).to_string();
    let user_handle = B64Url::from(user.id.to_vec()).to_string();

    let (key_algorithm, key_curve) = derive_algorithm_from_cose_key(&value.key)?;

    let extension_state =
        extension_state_from_hmac_secret(value.extensions.hmac_secret.as_ref(), None)?;

    Ok(Fido2CredentialFullView {
        credential_id: guid_bytes_to_string(&cred_id)?,
        key_type: "public-key".to_owned(),
        key_algorithm,
        key_curve,
        key_value,
        rp_id: value.rp_id,
        rp_name: rp.name,
        user_handle: Some(user_handle),

        counter: value.counter.unwrap_or(0).to_string(),
        user_name: user.name,
        user_display_name: user.display_name,
        discoverable: options.rk.to_string(),
        creation_date: chrono::offset::Utc::now(),
        extension_state,
    })
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
#[error("Input should be a 16 byte array")]
pub struct InvalidInputLengthError;

#[allow(missing_docs)]
pub fn guid_bytes_to_string(source: &[u8]) -> Result<String, InvalidInputLengthError> {
    if source.len() != 16 {
        return Err(InvalidInputLengthError);
    }
    Ok(uuid::Uuid::from_bytes(source.try_into().expect("Invalid length")).to_string())
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
#[error("Invalid GUID")]
pub struct InvalidGuidError;

#[allow(missing_docs)]
pub fn string_to_guid_bytes(source: &str) -> Result<Vec<u8>, InvalidGuidError> {
    if source.starts_with("b64.") {
        let bytes =
            B64Url::try_from(source.trim_start_matches("b64.")).map_err(|_| InvalidGuidError)?;
        Ok(bytes.as_bytes().to_vec())
    } else {
        let Ok(uuid) = uuid::Uuid::try_parse(source) else {
            return Err(InvalidGuidError);
        };
        Ok(uuid.as_bytes().to_vec())
    }
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
#[error("Unknown enum value")]
pub struct UnknownEnumError;

// Some utilities to convert back and forth between enums and strings
fn get_enum_from_string_name<T: serde::de::DeserializeOwned>(
    s: &str,
) -> Result<T, UnknownEnumError> {
    let serialized = format!(r#""{s}""#);
    let deserialized: T = serde_json::from_str(&serialized).map_err(|_| UnknownEnumError)?;
    Ok(deserialized)
}

fn get_string_name_from_enum(s: impl serde::Serialize) -> Result<String, serde_json::Error> {
    let serialized = serde_json::to_string(&s)?;
    let deserialized: String = serde_json::from_str(&serialized)?;
    Ok(deserialized)
}

#[cfg(test)]
mod tests {
    use bitwarden_encoding::B64Url;
    use bitwarden_vault::{Fido2CredentialFullView, Fido2ExtensionStateView};
    use coset::{Label, RegisteredLabel, RegisteredLabelWithPrivate, iana::EnumI64};
    use passkey::types::webauthn::AuthenticatorAttachment;

    use super::{
        Fido2Error, FillCredentialError, StoredHmacSecret, derive_algorithm_from_cose_key,
        extension_state_from_hmac_secret, get_enum_from_string_name, get_string_name_from_enum,
        pkcs8_to_cose_key, stored_hmac_secret_from_extension_state,
    };

    const TEST_KEY_VALUE: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPzvtWYWmIsvqqr3LsZB0K-cbjuhJSGTGziL1LksHAPShRANCAAT-vqHTyEDS9QBNNi2BNLyu6TunubJT_L3G3i7KLpEDhMD15hi24IjGBH0QylJIrvlT4JN2tdRGF436XGc-VoAl";

    fn extension_state() -> Fido2ExtensionStateView {
        Fido2ExtensionStateView {
            prf_hmac_algorithm: "hmac-secret".to_string(),
            uv_hmac_seed: B64Url::from(vec![0x11; 32]).to_string(),
            non_uv_hmac_seed: Some(B64Url::from(vec![0x22; 32]).to_string()),
            cred_blob: None,
            large_blob: None,
            key_algorithm_metadata: "ES256".to_string(),
        }
    }

    fn full_view(extension_state: Option<Fido2ExtensionStateView>) -> Fido2CredentialFullView {
        Fido2CredentialFullView {
            credential_id: "b64.1UiCbnm020Cj2BERb36DSQ".to_string(),
            key_type: "public-key".to_string(),
            key_algorithm: "ECDSA".to_string(),
            key_curve: "P-256".to_string(),
            key_value: TEST_KEY_VALUE.to_string(),
            rp_id: "nuri.com".to_string(),
            user_handle: Some("YWxleCBtdWxsZXI".to_string()),
            user_name: Some("test@nuri.com".to_string()),
            counter: "0".to_string(),
            rp_name: Some("Nuri".to_string()),
            user_display_name: Some("Test User".to_string()),
            discoverable: "true".to_string(),
            creation_date: chrono::offset::Utc::now(),
            extension_state,
        }
    }

    fn cose_key() -> coset::CoseKey {
        let key = B64Url::try_from(TEST_KEY_VALUE).unwrap();
        pkcs8_to_cose_key(key.as_bytes()).unwrap()
    }

    #[test]
    fn test_enum_string_conversion_works_as_expected() {
        assert_eq!(
            get_string_name_from_enum(AuthenticatorAttachment::CrossPlatform).unwrap(),
            "cross-platform"
        );

        assert_eq!(
            get_enum_from_string_name::<AuthenticatorAttachment>("cross-platform").unwrap(),
            AuthenticatorAttachment::CrossPlatform
        );
    }

    #[test]
    fn string_to_guid_with_uuid_works() {
        let uuid = "d548826e-79b4-db40-a3d8-11116f7e8349";
        let bytes = super::string_to_guid_bytes(uuid).unwrap();
        assert_eq!(
            bytes,
            vec![
                213, 72, 130, 110, 121, 180, 219, 64, 163, 216, 17, 17, 111, 126, 131, 73
            ]
        );
    }

    #[test]
    fn string_to_guid_with_b64_works() {
        let b64 = "b64.1UiCbnm020Cj2BERb36DSQ";
        let bytes = super::string_to_guid_bytes(b64).unwrap();
        assert_eq!(
            bytes,
            vec![
                213, 72, 130, 110, 121, 180, 219, 64, 163, 216, 17, 17, 111, 126, 131, 73
            ]
        );
    }

    #[test]
    fn test_try_from_credential_full_view_bridges_hmac_state() {
        let passkey =
            super::try_from_credential_full_view(full_view(Some(extension_state()))).unwrap();

        let hmac = passkey
            .extensions
            .hmac_secret
            .as_ref()
            .expect("hmac_secret should be bridged from extension_state");
        assert_eq!(hmac.cred_with_uv, vec![0x11; 32]);
        assert_eq!(hmac.cred_without_uv, Some(vec![0x22; 32]));
    }

    #[test]
    fn test_try_from_credential_full_view_without_extension_state() {
        let passkey = super::try_from_credential_full_view(full_view(None)).unwrap();
        assert!(
            passkey.extensions.hmac_secret.is_none(),
            "hmac_secret should be None when extension_state is None"
        );
    }

    #[test]
    fn stored_hmac_secret_rejects_invalid_base64_and_seed_lengths() {
        let mut invalid_base64 = extension_state();
        invalid_base64.uv_hmac_seed = "%".to_string();
        assert!(matches!(
            stored_hmac_secret_from_extension_state(Some(&invalid_base64)),
            Err(Fido2Error::Decode(_))
        ));

        let mut short_uv = extension_state();
        short_uv.uv_hmac_seed = B64Url::from(vec![0x11; 31]).to_string();
        assert!(matches!(
            stored_hmac_secret_from_extension_state(Some(&short_uv)),
            Err(Fido2Error::InvalidHmacSeedLength {
                field: "UV",
                actual: 31
            })
        ));

        let mut long_non_uv = extension_state();
        long_non_uv.non_uv_hmac_seed = Some(B64Url::from(vec![0x22; 33]).to_string());
        assert!(matches!(
            stored_hmac_secret_from_extension_state(Some(&long_non_uv)),
            Err(Fido2Error::InvalidHmacSeedLength {
                field: "non-UV",
                actual: 33
            })
        ));
    }

    #[test]
    fn stored_hmac_secret_rejects_unknown_algorithm() {
        let mut state = extension_state();
        state.prf_hmac_algorithm = "future-algorithm".to_string();
        assert!(matches!(
            stored_hmac_secret_from_extension_state(Some(&state)),
            Err(Fido2Error::UnsupportedHmacAlgorithm(algorithm))
                if algorithm == "future-algorithm"
        ));
    }

    #[test]
    fn extension_update_preserves_opaque_fields() {
        let existing = Fido2ExtensionStateView {
            prf_hmac_algorithm: "hmac-secret".to_string(),
            uv_hmac_seed: B64Url::from(vec![0x01; 32]).to_string(),
            non_uv_hmac_seed: Some(B64Url::from(vec![0x02; 32]).to_string()),
            cred_blob: Some("opaque-cred-blob".to_string()),
            large_blob: Some("opaque-large-blob".to_string()),
            key_algorithm_metadata: "opaque-key-metadata".to_string(),
        };
        let updated_hmac = StoredHmacSecret {
            cred_with_uv: vec![0x11; 32],
            cred_without_uv: Some(vec![0x22; 32]),
        };

        let updated = extension_state_from_hmac_secret(Some(&updated_hmac), Some(&existing))
            .unwrap()
            .unwrap();

        assert_eq!(
            updated.uv_hmac_seed,
            B64Url::from(vec![0x11; 32]).to_string()
        );
        assert_eq!(
            updated.non_uv_hmac_seed,
            Some(B64Url::from(vec![0x22; 32]).to_string())
        );
        assert_eq!(updated.cred_blob, existing.cred_blob);
        assert_eq!(updated.large_blob, existing.large_blob);
        assert_eq!(
            updated.key_algorithm_metadata,
            existing.key_algorithm_metadata
        );
    }

    #[test]
    fn extension_update_rejects_invalid_outgoing_seed_length() {
        let hmac = StoredHmacSecret {
            cred_with_uv: vec![0x11; 31],
            cred_without_uv: None,
        };
        assert!(matches!(
            extension_state_from_hmac_secret(Some(&hmac), None),
            Err(FillCredentialError::InvalidHmacSeedLength {
                field: "UV",
                actual: 31
            })
        ));
    }

    #[test]
    fn cose_algorithm_derivation_accepts_only_es256_ec2_p256() {
        assert_eq!(
            derive_algorithm_from_cose_key(&cose_key()).unwrap(),
            ("ECDSA".to_string(), "P-256".to_string())
        );

        let mut missing_algorithm = cose_key();
        missing_algorithm.alg = None;
        assert!(matches!(
            derive_algorithm_from_cose_key(&missing_algorithm),
            Err(FillCredentialError::UnsupportedAlgorithm(_))
        ));

        let mut wrong_algorithm = cose_key();
        wrong_algorithm.alg = Some(RegisteredLabelWithPrivate::Assigned(
            coset::iana::Algorithm::RS256,
        ));
        assert!(matches!(
            derive_algorithm_from_cose_key(&wrong_algorithm),
            Err(FillCredentialError::UnsupportedAlgorithm(_))
        ));

        let mut wrong_key_type = cose_key();
        wrong_key_type.kty = RegisteredLabel::Assigned(coset::iana::KeyType::RSA);
        assert!(matches!(
            derive_algorithm_from_cose_key(&wrong_key_type),
            Err(FillCredentialError::UnsupportedAlgorithm(_))
        ));

        let mut missing_curve = cose_key();
        missing_curve
            .params
            .retain(|(label, _)| label != &Label::Int(-1));
        assert!(matches!(
            derive_algorithm_from_cose_key(&missing_curve),
            Err(FillCredentialError::UnsupportedAlgorithm(_))
        ));

        let mut wrong_curve = cose_key();
        let (_, curve) = wrong_curve
            .params
            .iter_mut()
            .find(|(label, _)| label == &Label::Int(-1))
            .unwrap();
        *curve =
            coset::cbor::value::Value::Integer(coset::iana::EllipticCurve::P_384.to_i64().into());
        assert!(matches!(
            derive_algorithm_from_cose_key(&wrong_curve),
            Err(FillCredentialError::UnsupportedAlgorithm(_))
        ));
    }
}
