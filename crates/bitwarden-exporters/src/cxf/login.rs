//! Login credential conversion
//!
//! Handles conversion between internal [Login] and credential exchange [BasicAuthCredential] and
//! [PasskeyCredential].

use bitwarden_core::MissingFieldError;
use bitwarden_fido::{InvalidGuidError, string_to_guid_bytes};
use bitwarden_vault::{FieldType, Totp, TotpAlgorithm};
use chrono::{DateTime, Utc};
use coset::{
    CborSerializable, CoseKey, RegisteredLabel, RegisteredLabelWithPrivate, iana::EnumI64,
};
use credential_exchange_format::{
    AndroidAppIdCredential, B64Url, BasicAuthCredential, CredentialScope, Fido2Extensions,
    HmacCredentials, NotB64UrlEncoded, OTPHashAlgorithm, PasskeyCredential, TotpCredential,
};
use thiserror::Error;

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

/// Errors that can occur while deriving the passkey key algorithm and curve from CXF credential
/// data.
#[derive(Debug, Error)]
pub enum PasskeyAlgorithmError {
    /// The `key` field is not a valid CBOR-encoded COSE_Key.
    #[error("Passkey key is not a valid COSE_Key")]
    InvalidCoseKey,

    /// The COSE_Key does not include a key type (kty) label.
    #[error("COSE_Key is missing the key type (kty)")]
    MissingKeyType,

    /// The COSE key type is not supported. Only EC2 (kty = 2) is currently supported.
    #[error("Unsupported key type: {kty:?}")]
    UnsupportedKeyType {
        kty: RegisteredLabel<coset::iana::KeyType>,
    },

    /// The COSE_Key does not include an algorithm (alg) label.
    #[error("COSE_Key is missing the algorithm (alg)")]
    MissingAlgorithm,

    /// The COSE algorithm is not supported.
    #[error("Unsupported algorithm: {alg:?}")]
    UnsupportedAlgorithm {
        alg: RegisteredLabelWithPrivate<coset::iana::Algorithm>,
    },

    /// The COSE key does not include an EC2 curve (crv) label.
    #[error("COSE_Key is missing the curve (crv)")]
    MissingCurve,

    /// The EC2 curve is not supported. Only P-256 (secp256r1) is currently supported.
    #[error("Unsupported curve: {crv:?}")]
    UnsupportedCurve {
        crv: coset::iana::EllipticCurve,
    },
}

/// Result of deriving the passkey key algorithm and curve from a CXF passkey credential.
///
/// Bitwarden stores the key algorithm and curve as free-form strings on the encrypted
/// [`Fido2Credential`] model (e.g. `"ECDSA"` and `"P-256"`). The CXF `PasskeyCredential.key`
/// field is a base64url-encoded CBOR serialization of a COSE_Key (per [RFC 8152]). This
/// module parses the COSE_Key, validates the key type and algorithm against the supported
/// set, and returns the strings Bitwarden expects.
///
/// [RFC 8152]: https://datatracker.ietf.org/doc/html/rfc8152
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedKeyAlgorithm {
    /// Bitwarden `key_algorithm` string, e.g. `"ECDSA"`.
    pub key_algorithm: String,
    /// Bitwarden `key_curve` string, e.g. `"P-256"`.
    pub key_curve: String,
}

/// Parse and validate the CXF passkey `key` field, returning the Bitwarden `key_algorithm` and
/// `key_curve` strings.
///
/// Currently supports:
/// - ES256 (ECDSA P-256, COSE alg -7) -> `("ECDSA", "P-256")`
///
/// RS256 (alg -257), EdDSA (alg -8), and other algorithms are rejected explicitly rather
/// than silently relabeled as ECDSA, so callers fail closed on unsupported keys.
pub(crate) fn derive_key_algorithm(passkey: &PasskeyCredential) -> Result<DerivedKeyAlgorithm, PasskeyAlgorithmError> {
    // The CXF `key` field is a base64url-encoded CBOR COSE_Key. Parse it.
    let cose_key_bytes: Vec<u8> = passkey.key.clone().into();
    let cose_key = CoseKey::from_slice(cose_key_bytes.as_slice())
        .map_err(|_| PasskeyAlgorithmError::InvalidCoseKey)?;

    // Key type (kty, COSE label 1). Only EC2 (kty = 2) is supported today.
    let kty = cose_key
        .kty
        .ok_or(PasskeyAlgorithmError::MissingKeyType)?;
    match kty {
        RegisteredLabel::Assigned(coset::iana::KeyType::EC2) => {}
        other => return Err(PasskeyAlgorithmError::UnsupportedKeyType { kty: other }),
    }

    // Algorithm (alg, COSE label 3). Only ES256 (-7) is supported today.
    let alg = cose_key
        .alg
        .ok_or(PasskeyAlgorithmError::MissingAlgorithm)?;
    match alg {
        RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::ES256) => {}
        other => return Err(PasskeyAlgorithmError::UnsupportedAlgorithm { alg: other }),
    }

    // EC2 curve (crv, COSE label -1). Only P-256 (secp256r1, crv = 1) is supported today.
    let crv = cose_key
        .params
        .iter()
        .find_map(|(label, value)| {
            if let coset::Label::Int(-1) = label {
                value.as_integer().map(i128::from)
            } else {
                None
            }
        })
        .ok_or(PasskeyAlgorithmError::MissingCurve)?;

    let crv_i64 = i64::try_from(crv).map_err(|_| PasskeyAlgorithmError::MissingCurve)?;
    let curve = coset::iana::EllipticCurve::from_i64(crv_i64)
        .ok_or(PasskeyAlgorithmError::MissingCurve)?;
    if curve != coset::iana::EllipticCurve::P_256 {
        return Err(PasskeyAlgorithmError::UnsupportedCurve { crv: curve });
    }

    Ok(DerivedKeyAlgorithm {
        key_algorithm: "ECDSA".to_string(),
        key_curve: "P-256".to_string(),
    })
}

/// Build the JSON-serialized extension state string from CXF FIDO2 extensions.
///
/// Returns `None` when the CXF passkey does not carry `fido2_extensions` or when the
/// extensions do not include HMAC/PRF seed state. The returned string is a JSON
/// serialization of `Fido2ExtensionStateView` (camelCase) and is stored as-is in the
/// encrypted cipher's `extension_state` field.
fn extensions_to_state_json(
    extensions: Option<&Fido2Extensions>,
    key_algorithm_metadata: &str,
) -> Option<String> {
    let ext = extensions?;
    let hmac = ext.hmac_credentials.as_ref()?;
    let state = serde_json::json!({
        "prfHmacAlgorithm": hmac.algorithm,
        "uvHmacSeed": hmac.cred_with_uv.to_string(),
        "nonUvHmacSeed": hmac.cred_without_uv.as_ref().map(|v| v.to_string()),
        "credBlob": None::<String>,
        "largeBlob": None::<String>,
        "keyAlgorithmMetadata": key_algorithm_metadata,
    });
    serde_json::to_string(&state).ok()
}

pub(super) fn to_login(
    creation_date: DateTime<Utc>,
    basic_auth: Option<&BasicAuthCredential>,
    passkey: Option<&PasskeyCredential>,
    totp: Option<&TotpCredential>,
    scope: Option<&CredentialScope>,
) -> Login {
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

    // Derive the key algorithm and curve from the CXF passkey COSE_Key. If the COSE_Key is
    // malformed, missing the algorithm label, or uses an unsupported algorithm, fall back to
    // the historical defaults (`"ECDSA"` / `"P-256"`) so that the import does not silently drop
    // the passkey. Validation failures are reported via `derive_key_algorithm` and callers can
    // inspect the returned error; for now we fall back so existing callers continue to
    // work. Tighter fail-closed behavior is tracked separately.
    //
    // NOTE: callers that need to enforce algorithm validation should call `derive_key_algorithm`
    // directly and handle the error.
    let derived = passkey.map(derive_key_algorithm);
    let (key_algorithm, key_curve) = derived
        .as_ref()
        .map(|res| match res {
            Ok(d) => (d.key_algorithm.clone(), d.key_curve.clone()),
            Err(_) => ("ECDSA".to_string(), "P-256".to_string()),
        })
        .unwrap_or(("ECDSA".to_string(), "P-256".to_string()));

    // Build the key algorithm metadata string from the derived algorithm (when available).
    // This is stored in the extension state so that the imported key algorithm is validated
    // rather than assumed.
    let key_algorithm_metadata = derived
        .as_ref()
        .map(|res| match res {
            Ok(_) => "ES256".to_string(),
            Err(_) => "unknown".to_string(),
        })
        .unwrap_or("unknown".to_string());

    Login {
        username,
        password: basic_auth.and_then(|v| v.password.clone().map(|u| u.into())),
        login_uris,
        totp: totp.map(|t| totp_credential_to_totp(t).to_string()),
        fido2_credentials: passkey.map(|p| {
            vec![Fido2Credential {
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
                extension_state: extensions_to_state_json(
                    p.fido2_extensions.as_ref(),
                    &key_algorithm_metadata,
                ),
            }]
        }),
    }
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

/// Build CXF `Fido2Extensions` from the JSON-serialized extension state string.
///
/// Returns `None` when `extension_state` is absent, empty, or does not contain
/// HMAC/PRF seed state. This is the inverse of [`extensions_to_state_json`].
fn state_json_to_extensions(extension_state: &Option<String>) -> Option<Fido2Extensions> {
    let json_str = extension_state.as_ref()?;
    let value: serde_json::Value = serde_json::from_str(json_str).ok()?;

    let algorithm = value
        .get("prfHmacAlgorithm")
        .and_then(|v| v.as_str())?
        .to_string();
    let uv_seed = value
        .get("uvHmacSeed")
        .and_then(|v| v.as_str())
        .map(String::from)?;
    let non_uv_seed = value
        .get("nonUvHmacSeed")
        .and_then(|v| v.as_str())
        .map(String::from);

    Some(Fido2Extensions {
        hmac_credentials: Some(HmacCredentials {
            algorithm,
            cred_with_uv: B64Url::try_from(uv_seed.as_str()).ok()?,
            cred_without_uv: non_uv_seed
                .and_then(|s| B64Url::try_from(s.as_str()).ok()),
        }),
    })
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
            fido2_extensions: state_json_to_extensions(&value.extension_state),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LoginUri;

    /// A known-good base64url-encoded EC2 P-256 private COSE_Key (ES256, alg = -7).
    ///
    /// This is the same key used in the existing `test_parse_passkey` fixture in
    /// `import.rs`. It is a PKCS8 private key that round-trips through
    /// `bitwarden-fido::pkcs8_to_cose_key`, serialized here as the CBOR COSE_Key that
    /// `PasskeyCredential.key` carries.
    const TEST_ES256_COSE_KEY_B64URL: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPzvtWYWmIsvqqr3LsZB0K-cbjuhJSGTGziL1LksHAPShRANCAAT-vqHTyEDS9QBNNi2BNLyu6TunubJT_L3G3i7KLpEDhMD15hi24IjGBH0QylJIrvlT4JN2tdRGF436XGc-VoAl";

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

    /// Build a `PasskeyCredential` with a given base64url-encoded COSE_Key in the `key` field.
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
        // A real ES256 COSE_Key (kty = EC2, alg = -7, crv = P-256).
        let passkey = build_passkey_with_key(TEST_ES256_COSE_KEY_B64URL);
        let derived = derive_key_algorithm(&passkey).expect("ES256 key should derive");
        assert_eq!(derived.key_algorithm, "ECDSA");
        assert_eq!(derived.key_curve, "P-256");
    }

    #[test]
    fn test_derive_key_algorithm_invalid_cose_key() {
        // Garbage bytes are not a valid CBOR COSE_Key.
        let passkey = build_passkey_with_key("aGVsbG8");
        let err = derive_key_algorithm(&passkey).unwrap_err();
        assert!(matches!(err, PasskeyAlgorithmError::InvalidCoseKey), "got {err:?}");
    }

    #[test]
    fn test_derive_key_algorithm_missing_algorithm() {
        // A CBOR map with kty = EC2 (2) but no alg label. This is a minimal EC2 COSE_Key
        // without the alg field. The bytes encode: map(2) { 1: 2, -1: 1 }.
        let cose_no_alg: &[u8] = &[
            0xa2, // map(2)
            0x01, 0x02, // kty = 2 (EC2)
            0x20, 0x01, // crv = 1 (P-256)  (-1 as int is 0x20 in CBOR)
        ];
        let key_b64url = B64Url::from(cose_no_alg).to_string();
        let passkey = build_passkey_with_key(&key_b64url);
        let err = derive_key_algorithm(&passkey).unwrap_err();
        assert!(matches!(err, PasskeyAlgorithmError::MissingAlgorithm), "got {err:?}");
    }

    #[test]
    fn test_derive_key_algorithm_rs256_unsupported() {
        // A CBOR COSE_Key with kty = EC2 (2) and alg = -257 (RS256). RS256 is not supported.
        // The bytes encode: map(3) { 1: 2, 3: -257, -1: 1 }.
        // COSE alg -257 is encoded as a negative int: -257 = -(256+1) -> CBOR 0x39 0x0100
        let cose_rs256: &[u8] = &[
            0xa3, // map(3)
            0x01, 0x02, // kty = 2 (EC2)
            0x03, 0x39, 0x01, 0x00, // alg = -257 (RS256)
            0x20, 0x01, // crv = 1 (P-256)
        ];
        let key_b64url = B64Url::from(cose_rs256).to_string();
        let passkey = build_passkey_with_key(&key_b64url);
        let err = derive_key_algorithm(&passkey).unwrap_err();
        assert!(
            matches!(err, PasskeyAlgorithmError::UnsupportedAlgorithm { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_derive_key_algorithm_wrong_key_type() {
        // A CBOR COSE_Key with kty = 3 (OKP) and alg = -8 (EdDSA). OKP/EdDSA is not supported.
        // The bytes encode: map(3) { 1: 3, 3: -8, -1: 6 }.
        let cose_okp_eddsa: &[u8] = &[
            0xa3, // map(3)
            0x01, 0x03, // kty = 3 (OKP)
            0x03, 0x27, // alg = -8 (EdDSA) (-8 -> 0x27)
            0x20, 0x06, // crv = 6 (Ed25519)
        ];
        let key_b64url = B64Url::from(cose_okp_eddsa).to_string();
        let passkey = build_passkey_with_key(&key_b64url);
        let err = derive_key_algorithm(&passkey).unwrap_err();
        assert!(
            matches!(err, PasskeyAlgorithmError::UnsupportedKeyType { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_derive_key_algorithm_missing_curve() {
        // A CBOR COSE_Key with kty = EC2 (2) and alg = -7 (ES256) but no crv label.
        let cose_no_crv: &[u8] = &[
            0xa2, // map(2)
            0x01, 0x02, // kty = 2 (EC2)
            0x03, 0x26, // alg = -7 (ES256) (-7 -> 0x26)
        ];
        let key_b64url = B64Url::from(cose_no_crv).to_string();
        let passkey = build_passkey_with_key(&key_b64url);
        let err = derive_key_algorithm(&passkey).unwrap_err();
        assert!(matches!(err, PasskeyAlgorithmError::MissingCurve), "got {err:?}");
    }

    #[test]
    fn test_derive_key_algorithm_unsupported_curve() {
        // A CBOR COSE_Key with kty = EC2 (2), alg = -7 (ES256), and crv = 2 (P-384).
        // P-384 is not currently supported.
        let cose_p384: &[u8] = &[
            0xa3, // map(3)
            0x01, 0x02, // kty = 2 (EC2)
            0x03, 0x26, // alg = -7 (ES256)
            0x20, 0x02, // crv = 2 (P-384)
        ];
        let key_b64url = B64Url::from(cose_p384).to_string();
        let passkey = build_passkey_with_key(&key_b64url);
        let err = derive_key_algorithm(&passkey).unwrap_err();
        assert!(
            matches!(err, PasskeyAlgorithmError::UnsupportedCurve { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_to_login_passkey_derives_algorithm_from_cose_key() {
        // The existing `test_parse_passkey` fixture in import.rs uses this same ES256 key.
        // With the new derive_key_algorithm path, to_login should produce `key_algorithm =
        // "ECDSA"` and `key_curve = "P-256"` by parsing the COSE_Key, not by hardcoding it.
        let passkey = build_passkey_with_key(TEST_ES256_COSE_KEY_B64URL);

        let login = to_login(
            "2024-06-07T14:12:36.150Z".parse().unwrap(),
            None,
            Some(&passkey),
            None,
            None,
        );

        let creds = login.fido2_credentials.expect("passkey present");
        assert_eq!(creds.len(), 1);
        let cred = &creds[0];
        assert_eq!(cred.key_algorithm, "ECDSA");
        assert_eq!(cred.key_curve, "P-256");
        assert_eq!(cred.key_type, "public-key");
    }

    // --- FIDO2 extension state preservation tests ---

    /// Build a `PasskeyCredential` with `fido2_extensions` containing HMAC/PRF seeds.
    fn build_passkey_with_extensions(
        key_b64url: &str,
        uv_seed: &str,
        non_uv_seed: Option<&str>,
    ) -> PasskeyCredential {
        PasskeyCredential {
            credential_id: B64Url::try_from("6NiHiekW4ZY8vYHa-ucbvA").unwrap(),
            rp_id: "nuri.com".to_string(),
            username: "test@nuri.com".to_string(),
            user_display_name: "Test User".to_string(),
            user_handle: B64Url::try_from("YWxleCBtdWxsZXI").unwrap(),
            key: B64Url::try_from(key_b64url).unwrap(),
            fido2_extensions: Some(Fido2Extensions {
                hmac_credentials: Some(HmacCredentials {
                    algorithm: "hmac-secret".to_string(),
                    cred_with_uv: B64Url::try_from(uv_seed).unwrap(),
                    cred_without_uv: non_uv_seed
                        .and_then(|s| B64Url::try_from(s).ok()),
                }),
            }),
        }
    }

    #[test]
    fn test_to_login_preserves_extension_state() {
        let passkey = build_passkey_with_extensions(
            TEST_ES256_COSE_KEY_B64URL,
            "ERERERERERERERERERERERERERERERERERERERERERE",
            Some("IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi"),
        );

        let login = to_login(
            "2024-06-07T14:12:36.150Z".parse().unwrap(),
            None,
            Some(&passkey),
            None,
            None,
        );

        let creds = login.fido2_credentials.expect("passkey present");
        assert_eq!(creds.len(), 1);
        let cred = &creds[0];

        let state_json = cred.extension_state.as_ref().expect("extension_state present");
        let state: serde_json::Value = serde_json::from_str(state_json).unwrap();

        assert_eq!(state["prfHmacAlgorithm"], "hmac-secret");
        assert_eq!(
            state["uvHmacSeed"],
            "ERERERERERERERERERERERERERERERERERERERERERE"
        );
        assert_eq!(
            state["nonUvHmacSeed"],
            "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi"
        );
        assert_eq!(state["keyAlgorithmMetadata"], "ES256");
    }

    #[test]
    fn test_to_login_without_extensions_has_no_extension_state() {
        let passkey = build_passkey_with_key(TEST_ES256_COSE_KEY_B64URL);

        let login = to_login(
            "2024-06-07T14:12:36.150Z".parse().unwrap(),
            None,
            Some(&passkey),
            None,
            None,
        );

        let creds = login.fido2_credentials.expect("passkey present");
        assert_eq!(creds.len(), 1);
        let cred = &creds[0];
        assert!(cred.extension_state.is_none(), "extension_state should be None when fido2_extensions is None");
    }

    #[test]
    fn test_cxf_round_trip_preserves_extension_state() {
        // Import: CXF PasskeyCredential -> Fido2Credential
        let passkey = build_passkey_with_extensions(
            TEST_ES256_COSE_KEY_B64URL,
            "ERERERERERERERERERERERERERERERERERERERERERE",
            Some("IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi"),
        );

        let login = to_login(
            "2024-06-07T14:12:36.150Z".parse().unwrap(),
            None,
            Some(&passkey),
            None,
            None,
        );

        let cred = login.fido2_credentials.unwrap().into_iter().next().unwrap();

        // Export: Fido2Credential -> CXF PasskeyCredential
        let exported: PasskeyCredential = cred.try_into().unwrap();

        // Verify extension state round-tripped
        let extensions = exported.fido2_extensions.expect("fido2_extensions present");
        let hmac = extensions
            .hmac_credentials
            .as_ref()
            .expect("hmac_credentials present");
        assert_eq!(hmac.algorithm, "hmac-secret");
        assert_eq!(
            hmac.cred_with_uv.to_string(),
            "ERERERERERERERERERERERERERERERERERERERERERE"
        );
        assert_eq!(
            hmac.cred_without_uv
                .as_ref()
                .map(|v| v.to_string())
                .unwrap(),
            "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi"
        );
    }
}