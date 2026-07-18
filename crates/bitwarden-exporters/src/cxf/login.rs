//! Login credential conversion
//!
//! Handles conversion between internal [Login] and credential exchange [BasicAuthCredential] and
//! [PasskeyCredential].

use bitwarden_core::MissingFieldError;
use bitwarden_fido::{InvalidGuidError, string_to_guid_bytes};
use bitwarden_vault::{Fido2ExtensionStateView, FieldType, Totp, TotpAlgorithm};
use chrono::{DateTime, Utc};
use credential_exchange_format::{
    AndroidAppIdCredential, B64Url, BasicAuthCredential, CredentialScope, Fido2Extensions,
    Fido2HmacCredentialAlgorithm, NotB64UrlEncoded, OTPHashAlgorithm, PasskeyCredential,
    TotpCredential,
};
use p256::{SecretKey, pkcs8::DecodePrivateKey};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{Fido2Credential, Field, Login, LoginUri};

/// Prefix that indicates the URL is an Android app scheme.
const ANDROID_APP_SCHEME: &str = "androidapp://";

/// Convert CXF OTPHashAlgorithm to Bitwarden's TotpAlgorithm
/// Handles standard algorithms and special cases like Steam
fn convert_otp_algorithm(algorithm: &OTPHashAlgorithm) -> TotpAlgorithm {
    match algorithm {
        OTPHashAlgorithm::Sha1 => TotpAlgorithm::Sha1,
        OTPHashAlgorithm::Sha256 => TotpAlgorithm::Sha256,
        OTPHashAlgorithm::Sha512 => TotpAlgorithm::Sha512,
        OTPHashAlgorithm::Unknown(algo) if algo == "steam" => TotpAlgorithm::Steam,
        OTPHashAlgorithm::Unknown(_) | _ => TotpAlgorithm::Sha1, /* Default to SHA1 for unknown
                                                                  * algorithms */
    }
}

/// Convert CXF TotpCredential to Bitwarden's Totp struct
/// This ensures we use the exact same encoding and formatting as Bitwarden's core implementation
fn totp_credential_to_totp(cxf_totp: &TotpCredential) -> Totp {
    let algorithm = convert_otp_algorithm(&cxf_totp.algorithm);

    let secret_bytes: Vec<u8> = cxf_totp.secret.clone().into();

    Totp {
        account: cxf_totp.username.clone(),
        algorithm,
        digits: cxf_totp.digits as u32,
        issuer: cxf_totp.issuer.clone(),
        period: cxf_totp.period as u32,
        secret: secret_bytes,
    }
}

/// Errors that can occur while importing CXF passkey data.
#[derive(Debug, Error)]
pub(crate) enum PasskeyImportError {
    /// CXF requires PKCS#8 DER. The P-256 decoder also rejects keys on unsupported curves.
    #[error("Passkey key is not a valid PKCS#8 P-256 private key")]
    InvalidPkcs8P256Key,

    #[error("Unsupported FIDO2 HMAC credential algorithm: {0}")]
    UnsupportedHmacAlgorithm(String),

    #[error("Invalid {seed_name} HMAC seed length: expected 32 bytes, got {actual}")]
    InvalidHmacSeedLength {
        seed_name: &'static str,
        actual: usize,
    },

    #[error("Secure-payment-confirmation extension import is not supported")]
    UnsupportedPaymentsExtension,

    #[error("credBlob/largeBlob import without HMAC credentials is not supported")]
    ExtensionStateWithoutHmacCredentials,

    #[error("Unable to serialize FIDO2 extension state: {0}")]
    SerializeExtensionState(#[from] serde_json::Error),
}

/// Result of deriving the passkey key algorithm and curve from a CXF passkey credential.
///
/// Bitwarden stores the key algorithm and curve as free-form strings on the encrypted
/// [`Fido2Credential`] model (e.g. `"ECDSA"` and `"P-256"`). CXF stores the private key as
/// base64url-encoded PKCS#8 DER. The MVP deliberately accepts only P-256/ES256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedKeyAlgorithm {
    /// Bitwarden `key_algorithm` string, e.g. `"ECDSA"`.
    pub key_algorithm: String,
    /// Bitwarden `key_curve` string, e.g. `"P-256"`.
    pub key_curve: String,
}

pub(crate) fn derive_key_algorithm(
    passkey: &PasskeyCredential,
) -> Result<DerivedKeyAlgorithm, PasskeyImportError> {
    SecretKey::from_pkcs8_der(passkey.key.as_ref())
        .map_err(|_| PasskeyImportError::InvalidPkcs8P256Key)?;

    Ok(DerivedKeyAlgorithm {
        key_algorithm: "ECDSA".to_string(),
        key_curve: "P-256".to_string(),
    })
}

/// Build the JSON-serialized extension state string from CXF FIDO2 extensions.
///
/// Returns `None` when the CXF passkey does not carry HMAC/PRF seed state. Present extension
/// values are validated and preserved; unsupported or malformed values fail the whole import.
fn extensions_to_state_json(
    extensions: Option<&Fido2Extensions>,
    key_algorithm_metadata: &str,
) -> Result<Option<String>, PasskeyImportError> {
    let Some(ext) = extensions else {
        return Ok(None);
    };
    if ext.payments.is_some() {
        return Err(PasskeyImportError::UnsupportedPaymentsExtension);
    }
    let Some(hmac) = ext.hmac_credentials.as_ref() else {
        return if ext.cred_blob.is_some() || ext.large_blob.is_some() {
            Err(PasskeyImportError::ExtensionStateWithoutHmacCredentials)
        } else {
            Ok(None)
        };
    };

    match &hmac.algorithm {
        Fido2HmacCredentialAlgorithm::HmacSha256 => {}
        Fido2HmacCredentialAlgorithm::Other(value) => {
            return Err(PasskeyImportError::UnsupportedHmacAlgorithm(value.clone()));
        }
    }
    validate_seed("credWithUV", hmac.cred_with_uv.as_ref())?;
    validate_seed("credWithoutUV", hmac.cred_without_uv.as_ref())?;

    let state = Zeroizing::new(Fido2ExtensionStateView {
        // This is Bitwarden's established name for the CTAP hmac-secret/PRF capability.
        prf_hmac_algorithm: "hmac-secret".to_string(),
        uv_hmac_seed: hmac.cred_with_uv.to_string(),
        non_uv_hmac_seed: Some(hmac.cred_without_uv.to_string()),
        cred_blob: ext.cred_blob.as_ref().map(ToString::to_string),
        large_blob: ext
            .large_blob
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?,
        key_algorithm_metadata: key_algorithm_metadata.to_string(),
    });
    Ok(Some(serde_json::to_string(&*state)?))
}

fn validate_seed(seed_name: &'static str, seed: &[u8]) -> Result<(), PasskeyImportError> {
    const HMAC_SHA256_SEED_LENGTH: usize = 32;
    if seed.len() != HMAC_SHA256_SEED_LENGTH {
        return Err(PasskeyImportError::InvalidHmacSeedLength {
            seed_name,
            actual: seed.len(),
        });
    }
    Ok(())
}

pub(super) fn to_login(
    creation_date: DateTime<Utc>,
    basic_auth: Option<&BasicAuthCredential>,
    passkey: Option<&PasskeyCredential>,
    totp: Option<&TotpCredential>,
    scope: Option<&CredentialScope>,
) -> Result<Login, PasskeyImportError> {
    // Use basic_auth username first, fallback to non-empty passkey username
    let username = basic_auth
        .and_then(|v| v.username.clone().map(Into::into))
        .or_else(|| {
            passkey
                .filter(|p| !p.username.is_empty())
                .map(|p| p.username.clone())
        });

    // Use scope URIs first, fallback to passkey rp_id
    let login_uris = scope
        .map(to_uris)
        .or_else(|| passkey.map(|p| vec![passkey_rp_id_to_uri(&p.rp_id)]))
        .unwrap_or_default();

    let derived = passkey.map(derive_key_algorithm).transpose()?;
    let (key_algorithm, key_curve) = derived
        .map(|value| (value.key_algorithm, value.key_curve))
        .unwrap_or(("ECDSA".to_string(), "P-256".to_string()));

    let fido2_credentials = if let Some(p) = passkey {
        let extension_state = extensions_to_state_json(p.fido2_extensions.as_ref(), "ES256")?;
        Some(vec![Fido2Credential {
            credential_id: format!("b64.{}", p.credential_id),
            key_type: "public-key".to_string(),
            key_algorithm,
            key_curve,
            key_value: p.key.to_string(),
            rp_id: p.rp_id.clone(),
            user_handle: Some(p.user_handle.to_string()),
            user_name: Some(p.username.clone()),
            counter: 0,
            rp_name: Some(p.rp_id.clone()),
            user_display_name: Some(p.user_display_name.clone()),
            discoverable: "true".to_string(),
            creation_date,
            extension_state,
        }])
    } else {
        None
    };

    Ok(Login {
        username,
        password: basic_auth.and_then(|v| v.password.clone().map(|u| u.into())),
        login_uris,
        totp: totp.map(|t| totp_credential_to_totp(t).to_string()),
        fido2_credentials,
    })
}

/// Creates a LoginUri from a URL string
fn create_login_uri(uri: String) -> LoginUri {
    LoginUri {
        uri: Some(uri),
        r#match: None,
    }
}

/// Creates URIs from a passkey's rp_id, adding https:// prefix for domain-like strings
fn passkey_rp_id_to_uri(rp_id: &str) -> LoginUri {
    let uri = if rp_id.contains('.') && !rp_id.starts_with("http") {
        format!("https://{rp_id}")
    } else {
        rp_id.to_string()
    };
    create_login_uri(uri)
}

/// Converts a `CredentialScope` to a vector of `LoginUri` objects.
///
/// This is used for login credentials.
fn to_uris(scope: &CredentialScope) -> Vec<LoginUri> {
    let urls = scope.urls.iter().map(|u| create_login_uri(u.clone()));

    let android_apps = scope
        .android_apps
        .iter()
        .map(|a| create_login_uri(format!("{ANDROID_APP_SCHEME}{}", a.bundle_id)));

    urls.chain(android_apps).collect()
}

/// Converts a `CredentialScope` to a vector of `Field` objects.
///
/// This is used for non-login credentials.
#[allow(unused)]
pub(super) fn to_fields(scope: &CredentialScope) -> Vec<Field> {
    let urls = scope.urls.iter().enumerate().map(|(i, u)| Field {
        name: Some(format!("Url {}", i + 1)),
        value: Some(u.clone()),
        r#type: FieldType::Text as u8,
        linked_id: None,
    });

    let android_apps = scope.android_apps.iter().enumerate().map(|(i, a)| Field {
        name: Some(format!("Android App {}", i + 1)),
        value: Some(a.bundle_id.clone()),
        r#type: FieldType::Text as u8,
        linked_id: None,
    });

    urls.chain(android_apps).collect()
}

impl From<Login> for BasicAuthCredential {
    fn from(login: Login) -> Self {
        BasicAuthCredential {
            username: login.username.map(|v| v.into()),
            password: login.password.map(|v| v.into()),
        }
    }
}

impl From<Login> for CredentialScope {
    fn from(login: Login) -> Self {
        let (android_uris, urls): (Vec<_>, Vec<_>) = login
            .login_uris
            .into_iter()
            .filter_map(|u| u.uri)
            .partition(|uri| uri.starts_with(ANDROID_APP_SCHEME));

        let android_apps = android_uris
            .into_iter()
            .map(|uri| {
                let rest = uri.trim_start_matches(ANDROID_APP_SCHEME);
                AndroidAppIdCredential {
                    bundle_id: rest.to_string(),
                    certificate: None,
                    name: None,
                }
            })
            .collect();

        CredentialScope { urls, android_apps }
    }
}

#[derive(Error, Debug)]
pub enum PasskeyError {
    #[error("Counter is not zero")]
    CounterNotZero,
    #[error(transparent)]
    InvalidGuid(InvalidGuidError),
    #[error(transparent)]
    MissingField(MissingFieldError),
    #[error("Data isn't base64url encoded")]
    InvalidBase64(NotB64UrlEncoded),
}

impl TryFrom<Fido2Credential> for PasskeyCredential {
    type Error = PasskeyError;

    fn try_from(value: Fido2Credential) -> Result<Self, Self::Error> {
        if value.counter > 0 {
            return Err(PasskeyError::CounterNotZero);
        }

        Ok(PasskeyCredential {
            credential_id: string_to_guid_bytes(&value.credential_id)
                .map_err(PasskeyError::InvalidGuid)?
                .into(),
            rp_id: value.rp_id,
            username: value.user_name.unwrap_or_default(),
            user_display_name: value.user_display_name.unwrap_or_default(),
            user_handle: value
                .user_handle
                .map(|v| B64Url::try_from(v.as_str()))
                .transpose()
                .map_err(PasskeyError::InvalidBase64)?
                .ok_or(PasskeyError::MissingField(MissingFieldError("user_handle")))?,
            key: B64Url::try_from(value.key_value.as_str()).map_err(PasskeyError::InvalidBase64)?,
            // Exporting portable HMAC seeds is intentionally deferred to the separately reviewed
            // CXF export work. Import support must not make secrets exportable by accident.
            fido2_extensions: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use credential_exchange_format::{Fido2HmacCredentials, Fido2LargeBlob};

    use super::*;
    use crate::LoginUri;

    /// Known-good base64url-encoded PKCS#8 DER for an ES256/P-256 private key.
    const TEST_ES256_PKCS8_KEY_B64URL: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPzvtWYWmIsvqqr3LsZB0K-cbjuhJSGTGziL1LksHAPShRANCAAT-vqHTyEDS9QBNNi2BNLyu6TunubJT_L3G3i7KLpEDhMD15hi24IjGBH0QylJIrvlT4JN2tdRGF436XGc-VoAl";

    #[test]
    fn test_basic_auth() {
        let login = Login {
            username: Some("test@bitwarden.com".to_string()),
            password: Some("asdfasdfasdf".to_string()),
            login_uris: vec![LoginUri {
                uri: Some("https://vault.bitwarden.com".to_string()),
                r#match: None,
            }],
            totp: None,
            fido2_credentials: None,
        };

        let basic_auth: BasicAuthCredential = login.into();

        let username = basic_auth.username.as_ref().unwrap();
        assert_eq!(username.value.0, "test@bitwarden.com");
        assert!(username.label.is_none());

        let password = basic_auth.password.as_ref().unwrap();
        assert_eq!(password.value.0, "asdfasdfasdf");
        assert!(password.label.is_none());
    }

    #[test]
    fn test_credential_scope() {
        let login = Login {
            username: None,
            password: None,
            login_uris: vec![LoginUri {
                uri: Some("https://vault.bitwarden.com".to_string()),
                r#match: None,
            }],
            totp: None,
            fido2_credentials: None,
        };

        let scope: CredentialScope = login.into();

        assert_eq!(scope.urls, vec!["https://vault.bitwarden.com".to_string()]);
    }

    #[test]
    fn test_passkey() {
        let credential = Fido2Credential {
            credential_id: "e8d88789-e916-e196-3cbd-81dafae71bbc".to_string(),
            key_type: "public-key".to_string(),
            key_algorithm: "ECDSA".to_string(),
            key_curve: "P-256".to_string(),
            key_value: "AAECAwQFBg".to_string(),
            rp_id: "123".to_string(),
            user_handle: Some("AAECAwQFBg".to_string()),
            user_name: None,
            counter: 0,
            rp_name: None,
            user_display_name: None,
            discoverable: "true".to_string(),
            creation_date: "2024-06-07T14:12:36.150Z".parse().unwrap(),
            extension_state: None,
        };

        let passkey: PasskeyCredential = credential.try_into().unwrap();

        assert_eq!(passkey.credential_id.to_string(), "6NiHiekW4ZY8vYHa-ucbvA");
        assert_eq!(passkey.rp_id, "123");
        assert_eq!(passkey.username, "");
        assert_eq!(passkey.user_display_name, "");
        assert_eq!(String::from(passkey.user_handle.clone()), "AAECAwQFBg");
        assert_eq!(String::from(passkey.key.clone()), "AAECAwQFBg");
        assert!(passkey.fido2_extensions.is_none());
    }

    #[test]
    fn test_to_uris_with_urls_only() {
        let scope = CredentialScope {
            urls: vec![
                "https://vault.bitwarden.com".to_string(),
                "https://bitwarden.com".to_string(),
            ],
            android_apps: vec![],
        };

        let uris = to_uris(&scope);

        assert_eq!(
            uris,
            vec![
                LoginUri {
                    uri: Some("https://vault.bitwarden.com".to_string()),
                    r#match: None
                },
                LoginUri {
                    uri: Some("https://bitwarden.com".to_string()),
                    r#match: None
                },
            ]
        );
    }

    #[test]
    fn test_to_uris_with_android_apps_only() {
        let scope = CredentialScope {
            urls: vec![],
            android_apps: vec![
                credential_exchange_format::AndroidAppIdCredential {
                    bundle_id: "com.bitwarden.app".to_string(),
                    certificate: None,
                    name: None,
                },
                credential_exchange_format::AndroidAppIdCredential {
                    bundle_id: "com.example.app".to_string(),
                    certificate: None,
                    name: None,
                },
            ],
        };

        let uris = to_uris(&scope);

        assert_eq!(
            uris,
            vec![
                LoginUri {
                    uri: Some("androidapp://com.bitwarden.app".to_string()),
                    r#match: None
                },
                LoginUri {
                    uri: Some("androidapp://com.example.app".to_string()),
                    r#match: None
                },
            ]
        );
    }

    #[test]
    fn test_to_uris_with_mixed_urls_and_android_apps() {
        let scope = CredentialScope {
            urls: vec![
                "https://vault.bitwarden.com".to_string(),
                "https://bitwarden.com".to_string(),
            ],
            android_apps: vec![
                credential_exchange_format::AndroidAppIdCredential {
                    bundle_id: "com.bitwarden.app".to_string(),
                    certificate: None,
                    name: None,
                },
                credential_exchange_format::AndroidAppIdCredential {
                    bundle_id: "com.example.app".to_string(),
                    certificate: None,
                    name: None,
                },
            ],
        };

        let uris = to_uris(&scope);

        assert_eq!(
            uris,
            vec![
                LoginUri {
                    uri: Some("https://vault.bitwarden.com".to_string()),
                    r#match: None
                },
                LoginUri {
                    uri: Some("https://bitwarden.com".to_string()),
                    r#match: None
                },
                LoginUri {
                    uri: Some("androidapp://com.bitwarden.app".to_string()),
                    r#match: None
                },
                LoginUri {
                    uri: Some("androidapp://com.example.app".to_string()),
                    r#match: None
                },
            ]
        );
    }

    #[test]
    fn test_to_uris_with_empty_scope() {
        let scope = CredentialScope {
            urls: vec![],
            android_apps: vec![],
        };

        let uris = to_uris(&scope);

        assert!(uris.is_empty());
    }

    #[test]
    fn test_credential_scope_with_android_apps_only() {
        let login = Login {
            username: None,
            password: None,
            login_uris: vec![
                LoginUri {
                    uri: Some("androidapp://com.bitwarden.app".to_string()),
                    r#match: None,
                },
                LoginUri {
                    uri: Some("androidapp://com.example.app".to_string()),
                    r#match: None,
                },
            ],
            totp: None,
            fido2_credentials: None,
        };

        let scope: CredentialScope = login.into();
        assert!(scope.urls.is_empty());
        assert_eq!(scope.android_apps.len(), 2);
        assert_eq!(scope.android_apps[0].bundle_id, "com.bitwarden.app");
        assert_eq!(scope.android_apps[1].bundle_id, "com.example.app");
    }

    #[test]
    fn test_credential_scope_with_mixed_urls_and_android_apps() {
        let login = Login {
            username: None,
            password: None,
            login_uris: vec![
                LoginUri {
                    uri: Some("https://vault.bitwarden.com".to_string()),
                    r#match: None,
                },
                LoginUri {
                    uri: Some("androidapp://com.bitwarden.app".to_string()),
                    r#match: None,
                },
                LoginUri {
                    uri: Some("https://bitwarden.com".to_string()),
                    r#match: None,
                },
                LoginUri {
                    uri: Some("androidapp://com.example.app".to_string()),
                    r#match: None,
                },
            ],
            totp: None,
            fido2_credentials: None,
        };

        let scope: CredentialScope = login.into();
        assert_eq!(
            scope.urls,
            vec![
                "https://vault.bitwarden.com".to_string(),
                "https://bitwarden.com".to_string(),
            ]
        );
        assert_eq!(scope.android_apps.len(), 2);
        assert_eq!(scope.android_apps[0].bundle_id, "com.bitwarden.app");
        assert_eq!(scope.android_apps[1].bundle_id, "com.example.app");
    }

    #[test]
    fn test_to_fields() {
        let scope = CredentialScope {
            urls: vec![
                "https://vault.bitwarden.com".to_string(),
                "https://bitwarden.com".to_string(),
            ],
            android_apps: vec![
                credential_exchange_format::AndroidAppIdCredential {
                    bundle_id: "com.bitwarden.app".to_string(),
                    certificate: None,
                    name: None,
                },
                credential_exchange_format::AndroidAppIdCredential {
                    bundle_id: "com.example.app".to_string(),
                    certificate: None,
                    name: None,
                },
            ],
        };

        let fields = to_fields(&scope);
        assert_eq!(
            fields,
            vec![
                Field {
                    name: Some("Url 1".to_string()),
                    value: Some("https://vault.bitwarden.com".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Url 2".to_string()),
                    value: Some("https://bitwarden.com".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Android App 1".to_string()),
                    value: Some("com.bitwarden.app".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Android App 2".to_string()),
                    value: Some("com.example.app".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
            ]
        );
    }

    // TOTP tests
    #[test]
    fn test_totp_credential_to_totp_basic() {
        let totp = TotpCredential {
            secret: "Hello World!".as_bytes().to_vec().into(),
            period: 30,
            digits: 6,
            username: Some("test@example.com".to_string()),
            algorithm: OTPHashAlgorithm::Sha1,
            issuer: Some("Example".to_string()),
        };

        let bitwarden_totp = totp_credential_to_totp(&totp);
        let otpauth = bitwarden_totp.to_string();

        assert!(otpauth.starts_with("otpauth://totp/Example:test%40example%2Ecom?secret="));
        assert!(otpauth.contains("&issuer=Example"));
        // Default period (30) and digits (6) and algorithm (SHA1) should not be included
        assert!(!otpauth.contains("&period=30"));
        assert!(!otpauth.contains("&digits=6"));
        assert!(!otpauth.contains("&algorithm=SHA1"));
    }

    #[test]
    fn test_totp_credential_to_totp_custom_parameters() {
        let totp = TotpCredential {
            secret: "Hello World!".as_bytes().to_vec().into(),
            period: 60,
            digits: 8,
            username: Some("user".to_string()),
            algorithm: OTPHashAlgorithm::Sha256,
            issuer: Some("Custom Issuer".to_string()),
        };

        let bitwarden_totp = totp_credential_to_totp(&totp);
        let otpauth = bitwarden_totp.to_string();

        assert!(otpauth.contains("Custom%20Issuer:user"));
        assert!(otpauth.contains("&issuer=Custom%20Issuer"));
        assert!(otpauth.contains("&period=60"));
        assert!(otpauth.contains("&digits=8"));
        assert!(otpauth.contains("&algorithm=SHA256"));
    }

    // Algorithm conversion tests
    #[test]
    fn test_convert_otp_algorithm_sha1() {
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Sha1);
        assert_eq!(result, TotpAlgorithm::Sha1);
    }

    #[test]
    fn test_convert_otp_algorithm_sha256() {
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Sha256);
        assert_eq!(result, TotpAlgorithm::Sha256);
    }

    #[test]
    fn test_convert_otp_algorithm_sha512() {
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Sha512);
        assert_eq!(result, TotpAlgorithm::Sha512);
    }

    #[test]
    fn test_convert_otp_algorithm_steam() {
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Unknown("steam".to_string()));
        assert_eq!(result, TotpAlgorithm::Steam);
    }

    #[test]
    fn test_convert_otp_algorithm_steam_case_sensitive() {
        // Test that "steam" is case-sensitive
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Unknown("Steam".to_string()));
        assert_eq!(result, TotpAlgorithm::Sha1); // will default to SHA1
    }

    #[test]
    fn test_convert_otp_algorithm_unknown_empty() {
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Unknown("".to_string()));
        assert_eq!(result, TotpAlgorithm::Sha1); // will default to SHA1
    }

    #[test]
    fn test_convert_otp_algorithm_unknown_md5() {
        // Test an algorithm that might exist in other systems but isn't supported
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Unknown("md5".to_string()));
        assert_eq!(result, TotpAlgorithm::Sha1); // will default to SHA1
    }

    #[test]
    fn test_convert_otp_algorithm_unknown_whitespace() {
        // Test steam with whitespace (will not match)
        let result = convert_otp_algorithm(&OTPHashAlgorithm::Unknown(" steam ".to_string()));
        assert_eq!(result, TotpAlgorithm::Sha1); // will default to SHA1
    }

    // Tests for the new helper functions
    #[test]
    fn test_passkey_rp_id_to_uri_with_domain() {
        let uri = passkey_rp_id_to_uri("example.com");
        assert_eq!(uri.uri, Some("https://example.com".to_string()));
        assert_eq!(uri.r#match, None);
    }

    #[test]
    fn test_passkey_rp_id_to_uri_with_https() {
        let uri = passkey_rp_id_to_uri("https://example.com");
        assert_eq!(uri.uri, Some("https://example.com".to_string()));
        assert_eq!(uri.r#match, None);
    }

    #[test]
    fn test_passkey_rp_id_to_uri_without_domain() {
        let uri = passkey_rp_id_to_uri("localhost");
        assert_eq!(uri.uri, Some("localhost".to_string()));
        assert_eq!(uri.r#match, None);
    }

    #[test]
    fn test_create_login_uri() {
        let uri = create_login_uri("https://test.example".to_string());
        assert_eq!(uri.uri, Some("https://test.example".to_string()));
        assert_eq!(uri.r#match, None);
    }

    // --- Passkey key algorithm derivation tests ---

    /// Build a `PasskeyCredential` with a given base64url-encoded PKCS#8 key.
    fn build_passkey_with_key(key_b64url: &str) -> PasskeyCredential {
        PasskeyCredential {
            credential_id: B64Url::try_from("6NiHiekW4ZY8vYHa-ucbvA").unwrap(),
            rp_id: "example.com".to_string(),
            username: "test".to_string(),
            user_display_name: "Test User".to_string(),
            user_handle: B64Url::try_from("YWxleCBtdWxsZXI").unwrap(),
            key: B64Url::try_from(key_b64url).unwrap(),
            fido2_extensions: None,
        }
    }

    #[test]
    fn test_derive_key_algorithm_es256() {
        let passkey = build_passkey_with_key(TEST_ES256_PKCS8_KEY_B64URL);
        let derived = derive_key_algorithm(&passkey).expect("ES256 key should derive");
        assert_eq!(derived.key_algorithm, "ECDSA");
        assert_eq!(derived.key_curve, "P-256");
    }

    #[test]
    fn test_derive_key_algorithm_rejects_invalid_pkcs8() {
        let passkey = build_passkey_with_key("aGVsbG8");
        let err = derive_key_algorithm(&passkey).unwrap_err();
        assert!(
            matches!(err, PasskeyImportError::InvalidPkcs8P256Key),
            "got {err:?}"
        );
    }

    #[test]
    fn test_to_login_fails_closed_on_invalid_pkcs8() {
        let passkey = build_passkey_with_key("aGVsbG8");
        let err = to_login(
            "2024-06-07T14:12:36.150Z".parse().unwrap(),
            None,
            Some(&passkey),
            None,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, PasskeyImportError::InvalidPkcs8P256Key),
            "got {err:?}"
        );
    }

    #[test]
    fn test_to_login_passkey_derives_algorithm_from_pkcs8() {
        let passkey = build_passkey_with_key(TEST_ES256_PKCS8_KEY_B64URL);

        let login = to_login(
            "2024-06-07T14:12:36.150Z".parse().unwrap(),
            None,
            Some(&passkey),
            None,
            None,
        )
        .unwrap();

        let creds = login.fido2_credentials.expect("passkey present");
        assert_eq!(creds.len(), 1);
        let cred = &creds[0];
        assert_eq!(cred.key_algorithm, "ECDSA");
        assert_eq!(cred.key_curve, "P-256");
        assert_eq!(cred.key_type, "public-key");
    }

    // --- FIDO2 extension state preservation tests ---

    fn valid_extensions() -> Fido2Extensions {
        Fido2Extensions {
            hmac_credentials: Some(Fido2HmacCredentials {
                algorithm: Fido2HmacCredentialAlgorithm::HmacSha256,
                cred_with_uv: B64Url::from(vec![0x11; 32]),
                cred_without_uv: B64Url::from(vec![0x22; 32]),
            }),
            cred_blob: Some(B64Url::from(b"credential-blob".as_slice())),
            large_blob: Some(Fido2LargeBlob {
                uncompressed_size: 4,
                data: B64Url::from(b"blob".as_slice()),
            }),
            payments: None,
        }
    }

    fn build_passkey_with_extensions(extensions: Fido2Extensions) -> PasskeyCredential {
        let mut passkey = build_passkey_with_key(TEST_ES256_PKCS8_KEY_B64URL);
        passkey.rp_id = "nuri.com".to_string();
        passkey.fido2_extensions = Some(extensions);
        passkey
    }

    #[test]
    fn test_to_login_preserves_extension_state() {
        let extensions = valid_extensions();
        let expected_large_blob = serde_json::to_string(&extensions.large_blob).unwrap();
        let expected_uv = B64Url::from(vec![0x11; 32]).to_string();
        let expected_non_uv = B64Url::from(vec![0x22; 32]).to_string();
        let expected_cred_blob = B64Url::from(b"credential-blob".as_slice()).to_string();
        let passkey = build_passkey_with_extensions(extensions);

        let login = to_login(
            "2024-06-07T14:12:36.150Z".parse().unwrap(),
            None,
            Some(&passkey),
            None,
            None,
        )
        .unwrap();

        let creds = login.fido2_credentials.expect("passkey present");
        assert_eq!(creds.len(), 1);
        let cred = &creds[0];

        let state_json = cred
            .extension_state
            .as_ref()
            .expect("extension_state present");
        let state: Fido2ExtensionStateView = serde_json::from_str(state_json).unwrap();

        assert_eq!(state.prf_hmac_algorithm, "hmac-secret");
        assert_eq!(state.uv_hmac_seed, expected_uv);
        assert_eq!(
            state.non_uv_hmac_seed.as_deref(),
            Some(expected_non_uv.as_str())
        );
        assert_eq!(
            state.cred_blob.as_deref(),
            Some(expected_cred_blob.as_str())
        );
        assert_eq!(state.large_blob, Some(expected_large_blob));
        assert_eq!(state.key_algorithm_metadata, "ES256");
    }

    #[test]
    fn test_to_login_rejects_unknown_hmac_algorithm() {
        let mut extensions = valid_extensions();
        extensions.hmac_credentials.as_mut().unwrap().algorithm =
            Fido2HmacCredentialAlgorithm::Other("sha512".to_string());
        let passkey = build_passkey_with_extensions(extensions);

        let error = to_login(Utc::now(), None, Some(&passkey), None, None).unwrap_err();
        assert!(matches!(
            error,
            PasskeyImportError::UnsupportedHmacAlgorithm(value) if value == "sha512"
        ));
    }

    #[test]
    fn test_to_login_rejects_wrong_seed_length() {
        let mut extensions = valid_extensions();
        extensions.hmac_credentials.as_mut().unwrap().cred_with_uv = B64Url::from(vec![0x11; 31]);
        let passkey = build_passkey_with_extensions(extensions);

        let error = to_login(Utc::now(), None, Some(&passkey), None, None).unwrap_err();
        assert!(matches!(
            error,
            PasskeyImportError::InvalidHmacSeedLength {
                seed_name: "credWithUV",
                actual: 31
            }
        ));

        let mut extensions = valid_extensions();
        extensions
            .hmac_credentials
            .as_mut()
            .unwrap()
            .cred_without_uv = B64Url::from(vec![0x22; 33]);
        let passkey = build_passkey_with_extensions(extensions);
        let error = to_login(Utc::now(), None, Some(&passkey), None, None).unwrap_err();
        assert!(matches!(
            error,
            PasskeyImportError::InvalidHmacSeedLength {
                seed_name: "credWithoutUV",
                actual: 33
            }
        ));
    }

    #[test]
    fn test_to_login_rejects_payments_extension() {
        let mut extensions = valid_extensions();
        extensions.payments = Some(true);
        let passkey = build_passkey_with_extensions(extensions);

        let error = to_login(Utc::now(), None, Some(&passkey), None, None).unwrap_err();
        assert!(matches!(
            error,
            PasskeyImportError::UnsupportedPaymentsExtension
        ));
    }

    #[test]
    fn test_to_login_rejects_unrepresentable_extension_state() {
        let extensions = Fido2Extensions {
            cred_blob: Some(B64Url::from(b"credential-blob".as_slice())),
            ..Default::default()
        };
        let passkey = build_passkey_with_extensions(extensions);

        let error = to_login(Utc::now(), None, Some(&passkey), None, None).unwrap_err();
        assert!(matches!(
            error,
            PasskeyImportError::ExtensionStateWithoutHmacCredentials
        ));
    }

    #[test]
    fn test_to_login_without_extensions_has_no_extension_state() {
        let passkey = build_passkey_with_key(TEST_ES256_PKCS8_KEY_B64URL);

        let login = to_login(
            "2024-06-07T14:12:36.150Z".parse().unwrap(),
            None,
            Some(&passkey),
            None,
            None,
        )
        .unwrap();

        let creds = login.fido2_credentials.expect("passkey present");
        assert_eq!(creds.len(), 1);
        let cred = &creds[0];
        assert!(
            cred.extension_state.is_none(),
            "extension_state should be None when fido2_extensions is None"
        );
    }

    #[test]
    fn test_cxf_export_does_not_publish_extension_seeds_yet() {
        let passkey = build_passkey_with_extensions(valid_extensions());

        let login = to_login(
            "2024-06-07T14:12:36.150Z".parse().unwrap(),
            None,
            Some(&passkey),
            None,
            None,
        )
        .unwrap();

        let cred = login.fido2_credentials.unwrap().into_iter().next().unwrap();

        // Export: Fido2Credential -> CXF PasskeyCredential
        let exported: PasskeyCredential = cred.try_into().unwrap();

        assert!(exported.fido2_extensions.is_none());
    }
}
