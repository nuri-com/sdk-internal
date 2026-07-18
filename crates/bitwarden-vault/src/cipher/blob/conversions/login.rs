use super::{Fido2CredentialDataV1, Fido2CredentialFullView, LoginUriDataV1, LoginUriView};

// --- LoginUriView <-> LoginUriDataV1 ---

impl From<&LoginUriView> for LoginUriDataV1 {
    fn from(view: &LoginUriView) -> Self {
        Self {
            uri: view.uri.clone(),
            r#match: view.r#match,
        }
    }
}

impl From<&LoginUriDataV1> for LoginUriView {
    fn from(data: &LoginUriDataV1) -> Self {
        Self {
            uri: data.uri.clone(),
            r#match: data.r#match,
            uri_checksum: None,
        }
    }
}

// --- Fido2CredentialFullView <-> Fido2CredentialDataV1 ---

impl From<&Fido2CredentialFullView> for Fido2CredentialDataV1 {
    fn from(view: &Fido2CredentialFullView) -> Self {
        Self {
            credential_id: view.credential_id.clone(),
            key_type: view.key_type.clone(),
            key_algorithm: view.key_algorithm.clone(),
            key_curve: view.key_curve.clone(),
            key_value: view.key_value.clone(),
            rp_id: view.rp_id.clone(),
            user_handle: view.user_handle.clone(),
            user_name: view.user_name.clone(),
            counter: view.counter.parse().unwrap_or(0),
            rp_name: view.rp_name.clone(),
            user_display_name: view.user_display_name.clone(),
            discoverable: view.discoverable == "true",
            creation_date: view.creation_date,
            extension_state: view.extension_state.clone(),
        }
    }
}

impl From<&Fido2CredentialDataV1> for Fido2CredentialFullView {
    fn from(data: &Fido2CredentialDataV1) -> Self {
        Self {
            credential_id: data.credential_id.clone(),
            key_type: data.key_type.clone(),
            key_algorithm: data.key_algorithm.clone(),
            key_curve: data.key_curve.clone(),
            key_value: data.key_value.clone(),
            rp_id: data.rp_id.clone(),
            user_handle: data.user_handle.clone(),
            user_name: data.user_name.clone(),
            counter: data.counter.to_string(),
            rp_name: data.rp_name.clone(),
            user_display_name: data.user_display_name.clone(),
            discoverable: data.discoverable.to_string(),
            creation_date: data.creation_date,
            extension_state: data.extension_state.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{CompositeEncryptable, Decryptable};
    use bitwarden_encoding::B64Url;
    use chrono::{TimeZone, Utc};

    use super::super::{CipherBlobV1, CipherTypeDataV1, LoginUriDataV1, test_support::*};
    use crate::cipher::{
        cipher::CipherType,
        field::{FieldType, FieldView},
        linked_id::{LinkedIdType, LoginLinkedIdType},
        login::{
            Fido2Credential, Fido2CredentialFullView, Fido2ExtensionStateView, LoginUriView,
            LoginView, UriMatchType,
        },
    };

    fn test_extension_state() -> Fido2ExtensionStateView {
        Fido2ExtensionStateView {
            prf_hmac_algorithm: "hmac-secret".to_string(),
            uv_hmac_seed: B64Url::from(vec![0x11; 32]).to_string(),
            non_uv_hmac_seed: Some(B64Url::from(vec![0x22; 32]).to_string()),
            cred_blob: Some(B64Url::from(b"credential-blob".as_slice()).to_string()),
            large_blob: Some(r#"{"uncompressedSize":4,"data":"YmxvYg"}"#.to_string()),
            key_algorithm_metadata: "ES256".to_string(),
        }
    }

    #[test]
    fn test_login_uri_view_to_data_drops_checksum() {
        let view = LoginUriView {
            uri: Some("https://example.com".to_string()),
            r#match: Some(UriMatchType::Domain),
            uri_checksum: Some("some-checksum-value".to_string()),
        };

        let data = LoginUriDataV1::from(&view);

        assert_eq!(data.uri, Some("https://example.com".to_string()));
        assert_eq!(data.r#match, Some(UriMatchType::Domain));
    }

    #[test]
    fn test_login_uri_data_to_view_sets_checksum_none() {
        let data = LoginUriDataV1 {
            uri: Some("https://example.com".to_string()),
            r#match: Some(UriMatchType::Domain),
        };

        let view = LoginUriView::from(&data);

        assert_eq!(view.uri, Some("https://example.com".to_string()));
        assert_eq!(view.r#match, Some(UriMatchType::Domain));
        assert_eq!(view.uri_checksum, None);
    }

    #[test]
    fn test_fido2_counter_parsing() {
        let full_view = Fido2CredentialFullView {
            credential_id: "cred-id".to_string(),
            key_type: "public-key".to_string(),
            key_algorithm: "ECDSA".to_string(),
            key_curve: "P-256".to_string(),
            key_value: "key-value".to_string(),
            rp_id: "example.com".to_string(),
            user_handle: None,
            user_name: None,
            counter: "42".to_string(),
            rp_name: None,
            user_display_name: None,
            discoverable: "true".to_string(),
            creation_date: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            extension_state: None,
        };

        let data = super::Fido2CredentialDataV1::from(&full_view);
        assert_eq!(data.counter, 42);
        assert!(data.discoverable);

        let round_tripped = Fido2CredentialFullView::from(&data);
        assert_eq!(round_tripped.counter, "42");
        assert_eq!(round_tripped.discoverable, "true");
    }

    #[test]
    fn test_fido2_counter_zero() {
        let full_view = Fido2CredentialFullView {
            credential_id: "cred-id".to_string(),
            key_type: "public-key".to_string(),
            key_algorithm: "ECDSA".to_string(),
            key_curve: "P-256".to_string(),
            key_value: "key-value".to_string(),
            rp_id: "example.com".to_string(),
            user_handle: None,
            user_name: None,
            counter: "0".to_string(),
            rp_name: None,
            user_display_name: None,
            discoverable: "false".to_string(),
            creation_date: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            extension_state: None,
        };

        let data = super::Fido2CredentialDataV1::from(&full_view);
        assert_eq!(data.counter, 0);
        assert!(!data.discoverable);

        let round_tripped = Fido2CredentialFullView::from(&data);
        assert_eq!(round_tripped.counter, "0");
        assert_eq!(round_tripped.discoverable, "false");
    }

    #[test]
    fn test_fido2_counter_invalid_defaults_to_zero() {
        let full_view = Fido2CredentialFullView {
            credential_id: "cred-id".to_string(),
            key_type: "public-key".to_string(),
            key_algorithm: "ECDSA".to_string(),
            key_curve: "P-256".to_string(),
            key_value: "key-value".to_string(),
            rp_id: "example.com".to_string(),
            user_handle: None,
            user_name: None,
            counter: "not-a-number".to_string(),
            rp_name: None,
            user_display_name: None,
            discoverable: "true".to_string(),
            creation_date: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            extension_state: None,
        };

        let data = super::Fido2CredentialDataV1::from(&full_view);
        assert_eq!(data.counter, 0);
    }

    #[test]
    fn test_login_cipher_round_trip() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        // Create fido2 credentials by encrypting a FullView
        let expected_extension_state = test_extension_state();
        let fido2_full = Fido2CredentialFullView {
            credential_id: "cred-123".to_string(),
            key_type: "public-key".to_string(),
            key_algorithm: "ECDSA".to_string(),
            key_curve: "P-256".to_string(),
            key_value: "key-value-base64".to_string(),
            rp_id: "example.com".to_string(),
            user_handle: Some("user-handle".to_string()),
            user_name: Some("testuser".to_string()),
            counter: "42".to_string(),
            rp_name: Some("Example".to_string()),
            user_display_name: Some("Test User".to_string()),
            discoverable: "true".to_string(),
            creation_date: Utc.with_ymd_and_hms(2024, 6, 1, 10, 30, 0).unwrap(),
            extension_state: Some(expected_extension_state.clone()),
        };
        let encrypted_fido2: Fido2Credential =
            fido2_full.encrypt_composite(&mut ctx, key_id).unwrap();

        let original = crate::CipherView {
            name: "My Login".to_string(),
            notes: Some("Login notes".to_string()),
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: Some("testuser@example.com".to_string()),
                password: Some("p@ssw0rd123".to_string()),
                password_revision_date: Some(Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap()),
                uris: Some(vec![LoginUriView {
                    uri: Some("https://example.com/login".to_string()),
                    r#match: Some(UriMatchType::Domain),
                    uri_checksum: Some("some-checksum".to_string()),
                }]),
                totp: Some("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP".to_string()),
                autofill_on_page_load: Some(true),
                fido2_credentials: Some(vec![encrypted_fido2]),
            }),
            fields: Some(vec![FieldView {
                name: Some("Custom Field".to_string()),
                value: Some("custom-value".to_string()),
                r#type: FieldType::Linked,
                linked_id: Some(LinkedIdType::Login(LoginLinkedIdType::Username)),
            }]),
            password_history: Some(vec![crate::PasswordHistoryView {
                password: "old-password-1".to_string(),
                last_used_date: Utc.with_ymd_and_hms(2023, 12, 1, 8, 0, 0).unwrap(),
            }]),
            ..create_shell_cipher_view(CipherType::Login)
        };

        let blob = CipherBlobV1::from_cipher_view(&original, &mut ctx, key_id).unwrap();

        // Verify blob intermediate state
        assert_eq!(blob.name, "My Login");
        assert_eq!(blob.notes, Some("Login notes".to_string()));
        if let CipherTypeDataV1::Login(ref login_data) = blob.type_data {
            assert_eq!(
                login_data.username,
                Some("testuser@example.com".to_string())
            );
            assert_eq!(login_data.fido2_credentials.len(), 1);
            assert_eq!(login_data.fido2_credentials[0].counter, 42);
            assert!(login_data.fido2_credentials[0].discoverable);
            assert_eq!(
                login_data.fido2_credentials[0].extension_state.as_ref(),
                Some(&expected_extension_state)
            );
            // URI checksum should be dropped
            assert_eq!(login_data.uris.len(), 1);
        } else {
            panic!("Expected Login type data");
        }

        // Round-trip back
        let mut restored = create_shell_cipher_view(CipherType::Login);
        blob.apply_to_cipher_view(&mut restored, &mut ctx, key_id)
            .unwrap();

        assert_eq!(restored.name, "My Login");
        assert_eq!(restored.notes, Some("Login notes".to_string()));
        assert_eq!(restored.r#type, CipherType::Login);

        let login = restored.login.unwrap();
        assert_eq!(login.username, Some("testuser@example.com".to_string()));
        assert_eq!(login.password, Some("p@ssw0rd123".to_string()));
        assert_eq!(
            login.totp,
            Some("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP".to_string())
        );
        assert_eq!(login.autofill_on_page_load, Some(true));

        // URIs should round-trip but checksum is None
        let uris = login.uris.unwrap();
        assert_eq!(uris.len(), 1);
        assert_eq!(uris[0].uri, Some("https://example.com/login".to_string()));
        assert_eq!(uris[0].r#match, Some(UriMatchType::Domain));
        assert_eq!(uris[0].uri_checksum, None);

        // Fido2 credentials should be re-encrypted
        let fido2 = login.fido2_credentials.unwrap();
        assert_eq!(fido2.len(), 1);
        // Decrypt to verify content survived the round-trip
        let decrypted: Fido2CredentialFullView = fido2[0].decrypt(&mut ctx, key_id).unwrap();
        assert_eq!(decrypted.credential_id, "cred-123");
        assert_eq!(decrypted.counter, "42");
        assert_eq!(decrypted.discoverable, "true");
        assert_eq!(decrypted.rp_id, "example.com");
        assert_eq!(
            decrypted.extension_state.as_ref(),
            Some(&expected_extension_state)
        );

        // Fields and password history
        assert_eq!(restored.fields.as_ref().unwrap().len(), 1);
        assert_eq!(restored.password_history.as_ref().unwrap().len(), 1);

        assert!(restored.card.is_none());
        assert!(restored.identity.is_none());
        assert!(restored.secure_note.is_none());
        assert!(restored.ssh_key.is_none());
    }

    // --- Extension state preservation tests (issue #60) ---

    #[test]
    fn test_fido2_extension_state_round_trip_through_blob() {
        let extension_state = test_extension_state();

        let full_view = Fido2CredentialFullView {
            credential_id: "cred-id".to_string(),
            key_type: "public-key".to_string(),
            key_algorithm: "ECDSA".to_string(),
            key_curve: "P-256".to_string(),
            key_value: "key-value".to_string(),
            rp_id: "nuri.com".to_string(),
            user_handle: Some("ICEiIyQlJicoKSorLC0uLw".to_string()),
            user_name: Some("test@nuri.com".to_string()),
            counter: "0".to_string(),
            rp_name: Some("Nuri".to_string()),
            user_display_name: Some("Test User".to_string()),
            discoverable: "true".to_string(),
            creation_date: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            extension_state: Some(extension_state.clone()),
        };

        // View -> V1 Data -> View round trip
        let data = super::Fido2CredentialDataV1::from(&full_view);
        let round_tripped = Fido2CredentialFullView::from(&data);

        assert_eq!(round_tripped.credential_id, "cred-id");
        assert_eq!(round_tripped.rp_id, "nuri.com");
        assert_eq!(
            round_tripped.user_handle.as_deref(),
            Some("ICEiIyQlJicoKSorLC0uLw")
        );

        assert_eq!(round_tripped.extension_state, Some(extension_state));
    }

    #[test]
    fn test_fido2_blob_debug_redacts_private_key_and_hmac_seeds() {
        let extension_state = test_extension_state();
        let uv_seed = extension_state.uv_hmac_seed.clone();
        let non_uv_seed = extension_state
            .non_uv_hmac_seed
            .clone()
            .expect("test state should contain a non-UV seed");
        let private_key = "private-key-sentinel";
        let full_view = Fido2CredentialFullView {
            credential_id: "cred-id".to_string(),
            key_type: "public-key".to_string(),
            key_algorithm: "ECDSA".to_string(),
            key_curve: "P-256".to_string(),
            key_value: private_key.to_string(),
            rp_id: "nuri.com".to_string(),
            user_handle: None,
            user_name: None,
            counter: "0".to_string(),
            rp_name: None,
            user_display_name: None,
            discoverable: "true".to_string(),
            creation_date: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            extension_state: Some(extension_state),
        };

        let data = super::Fido2CredentialDataV1::from(&full_view);
        let debug = format!("{data:?}");

        assert!(!debug.contains(private_key));
        assert!(!debug.contains(&uv_seed));
        assert!(!debug.contains(&non_uv_seed));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn test_fido2_extension_state_none_remains_none_through_blob() {
        let full_view = Fido2CredentialFullView {
            credential_id: "cred-id".to_string(),
            key_type: "public-key".to_string(),
            key_algorithm: "ECDSA".to_string(),
            key_curve: "P-256".to_string(),
            key_value: "key-value".to_string(),
            rp_id: "nuri.com".to_string(),
            user_handle: None,
            user_name: None,
            counter: "0".to_string(),
            rp_name: None,
            user_display_name: None,
            discoverable: "true".to_string(),
            creation_date: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            extension_state: None,
        };

        let data = super::Fido2CredentialDataV1::from(&full_view);
        assert!(
            data.extension_state.is_none(),
            "extension_state should be None in V1 data"
        );

        let round_tripped = Fido2CredentialFullView::from(&data);
        assert!(
            round_tripped.extension_state.is_none(),
            "extension_state should remain None after round trip"
        );
    }

    #[test]
    fn test_fido2_extension_state_with_only_uv_seed() {
        // Tests that extension state with only a UV seed (no non-UV seed) round-trips correctly
        let mut extension_state = test_extension_state();
        extension_state.non_uv_hmac_seed = None;

        let full_view = Fido2CredentialFullView {
            credential_id: "cred-id".to_string(),
            key_type: "public-key".to_string(),
            key_algorithm: "ECDSA".to_string(),
            key_curve: "P-256".to_string(),
            key_value: "key-value".to_string(),
            rp_id: "nuri.com".to_string(),
            user_handle: Some("handle".to_string()),
            user_name: Some("user".to_string()),
            counter: "0".to_string(),
            rp_name: None,
            user_display_name: None,
            discoverable: "true".to_string(),
            creation_date: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            extension_state: Some(extension_state),
        };

        let data = super::Fido2CredentialDataV1::from(&full_view);
        let round_tripped = Fido2CredentialFullView::from(&data);

        let rt_state = round_tripped.extension_state.unwrap();
        assert_eq!(rt_state.prf_hmac_algorithm, "hmac-secret");
        assert_eq!(
            rt_state.uv_hmac_seed,
            B64Url::from(vec![0x11; 32]).to_string()
        );
        assert!(rt_state.non_uv_hmac_seed.is_none());
    }

    #[test]
    fn test_malformed_extension_state_fails_blob_deserialization() {
        let value = serde_json::json!({
            "credentialId": "cred-id",
            "keyType": "public-key",
            "keyAlgorithm": "ECDSA",
            "keyCurve": "P-256",
            "keyValue": "key-value",
            "rpId": "example.com",
            "userHandle": null,
            "userName": null,
            "counter": 0,
            "rpName": null,
            "userDisplayName": null,
            "discoverable": true,
            "creationDate": "2024-01-01T00:00:00Z",
            "extensionState": { "uvHmacSeed": 42 }
        });

        assert!(serde_json::from_value::<super::Fido2CredentialDataV1>(value).is_err());
    }
}
