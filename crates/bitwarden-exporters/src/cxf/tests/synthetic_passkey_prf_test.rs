#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use bitwarden_core::{Client, key_management::SymmetricKeySlotId};
    use bitwarden_crypto::SymmetricCryptoKey;
    use bitwarden_encoding::B64Url;
    use bitwarden_fido::{
        CheckUserOptions, CheckUserResult, Fido2Authenticator, Fido2CallbackError,
        Fido2CredentialStore, Fido2UserInterface, GetAssertionExtensionsInput,
        GetAssertionPrfInput, GetAssertionRequest, Options, PrfInputValues, UiHint, Verification,
    };
    use bitwarden_vault::{
        CipherListView, CipherView, EncryptionContext, Fido2CredentialFullView,
        Fido2CredentialNewView,
    };
    use credential_exchange_format::{Credential, Header, PasskeyCredential};
    use p256::{
        SecretKey,
        ecdsa::{Signature, VerifyingKey, signature::Verifier},
        elliptic_curve::sec1::ToEncodedPoint,
        pkcs8::DecodePrivateKey,
    };
    use sha2::{Digest, Sha256};

    use crate::ExporterClientExt;

    const FIXTURE: &str = include_str!("../../../resources/synthetic_passkey_prf_cxf_v1.json");
    const FIXTURE_SHA256: [u8; 32] = [
        0x15, 0xd5, 0x93, 0x5e, 0x40, 0xf9, 0x16, 0x94, 0x52, 0x5f, 0x8b, 0x09, 0xb1, 0xbb, 0xe1,
        0x34, 0xf3, 0x3e, 0xcb, 0xe5, 0xd1, 0x12, 0x12, 0xc4, 0x56, 0xd4, 0x25, 0x88, 0x2e, 0xa2,
        0xc1, 0x8b,
    ];
    const EXPECTED_CREDENTIAL_ID: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const EXPECTED_USER_HANDLE: &str = "ICEiIyQlJicoKSorLC0uLw";
    const EXPECTED_PUBLIC_KEY_SEC1: &str =
        "BP6-odPIQNL1AE02LYE0vK7pO6e5slP8vcbeLsoukQOEwPXmGLbgiMYEfRDKUkiu-VPgk3a11EYXjfpcZz5WgCU";
    const EXPECTED_UV_FIRST: &str = "d8i94nf9OSyRco1LXP3wnUrRte5rCmguP3cURrj06go";
    const EXPECTED_UV_SECOND: &str = "wxVdw-_rf1oJwrVQn-r6p4nqgf_dJgsfBDutwJNqdEY";
    const EXPECTED_NON_UV_FIRST: &str = "bC5nGXrEHZvqT8xWOygtFszTXK3xVFxUjKs81mCSZJc";
    const EXPECTED_NON_UV_SECOND: &str = "Nt9iqYcDEZ2LEUJqHn-H4uCga23ML6wUTuPmjM95dP4";
    const CLIENT_DATA_HASH: [u8; 32] = [0xa5; 32];

    fn decode_b64url(value: &str) -> Vec<u8> {
        B64Url::try_from(value).unwrap().into_bytes()
    }

    fn parse_fixture() -> (Header, PasskeyCredential) {
        let header: Header = serde_json::from_str(FIXTURE).unwrap();
        let credential = &header.accounts[0].items[0].credentials[0];
        let Credential::Passkey(passkey) = credential else {
            panic!("fixture credential must be a passkey");
        };

        (header.clone(), (**passkey).clone())
    }

    fn create_client() -> Client {
        let client = Client::new(None);
        let user_key: SymmetricCryptoKey =
            "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q=="
                .to_string()
                .try_into()
                .unwrap();

        #[allow(deprecated)]
        client
            .internal
            .get_key_store()
            .context_mut()
            .set_symmetric_key(SymmetricKeySlotId::User, user_key)
            .unwrap();

        client
    }

    struct MockUserInterface {
        user_verified: bool,
    }

    #[async_trait]
    impl Fido2UserInterface for MockUserInterface {
        async fn check_user<'a>(
            &self,
            _options: CheckUserOptions,
            _hint: UiHint<'a, CipherView>,
        ) -> Result<CheckUserResult, Fido2CallbackError> {
            Ok(CheckUserResult {
                user_present: true,
                user_verified: self.user_verified,
            })
        }

        async fn pick_credential_for_authentication(
            &self,
            available_credentials: Vec<CipherView>,
        ) -> Result<CipherView, Fido2CallbackError> {
            available_credentials
                .into_iter()
                .next()
                .ok_or_else(|| Fido2CallbackError::Unknown("no credential".to_string()))
        }

        async fn check_user_and_pick_credential_for_creation(
            &self,
            _options: CheckUserOptions,
            _new_credential: Fido2CredentialNewView,
        ) -> Result<(CipherView, CheckUserResult), Fido2CallbackError> {
            Err(Fido2CallbackError::Unknown(
                "credential creation is outside this test".to_string(),
            ))
        }

        fn is_verification_enabled(&self) -> bool {
            true
        }
    }

    struct MockCredentialStore {
        cipher: CipherView,
        saved: Mutex<Vec<EncryptionContext>>,
    }

    impl MockCredentialStore {
        fn new(cipher: CipherView) -> Self {
            Self {
                cipher,
                saved: Mutex::new(Vec::new()),
            }
        }

        fn save_count(&self) -> usize {
            self.saved.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl Fido2CredentialStore for MockCredentialStore {
        async fn find_credentials(
            &self,
            _ids: Option<Vec<Vec<u8>>>,
            _rp_id: String,
            _user_handle: Option<Vec<u8>>,
        ) -> Result<Vec<CipherView>, Fido2CallbackError> {
            Ok(vec![self.cipher.clone()])
        }

        async fn all_credentials(&self) -> Result<Vec<CipherListView>, Fido2CallbackError> {
            Ok(Vec::new())
        }

        async fn save_credential(
            &self,
            credential: EncryptionContext,
        ) -> Result<(), Fido2CallbackError> {
            self.saved.lock().unwrap().push(credential);
            Ok(())
        }
    }

    fn request(verification: Verification) -> GetAssertionRequest {
        GetAssertionRequest {
            rp_id: "nuri.com".to_string(),
            client_data_hash: CLIENT_DATA_HASH.to_vec(),
            allow_list: None,
            options: Options::from(CheckUserOptions {
                require_presence: true,
                require_verification: verification,
            }),
            extensions: Some(GetAssertionExtensionsInput {
                prf: Some(GetAssertionPrfInput {
                    eval: Some(PrfInputValues {
                        first: b"nuri-prf-salt-v1".to_vec(),
                        second: Some(b"test-salt-2".to_vec()),
                    }),
                    eval_by_credential: None,
                }),
            }),
        }
    }

    fn decrypt_fixture_credential(client: &Client, cipher: &CipherView) -> Fido2CredentialFullView {
        let mut context = client.internal.get_key_store().context();
        let credentials = cipher.get_fido2_credentials(&mut context).unwrap();
        assert_eq!(credentials.len(), 1);
        credentials.into_iter().next().unwrap()
    }

    fn encrypted_extension_state(cipher: &CipherView) -> String {
        cipher
            .login
            .as_ref()
            .and_then(|login| login.fido2_credentials.as_ref())
            .and_then(|credentials| credentials.first())
            .and_then(|credential| credential.extension_state.as_ref())
            .expect("encrypted extension state")
            .to_string()
    }

    fn assert_imported_identity(
        credential: &Fido2CredentialFullView,
        fixture_passkey: &PasskeyCredential,
    ) {
        assert_eq!(
            credential.credential_id,
            format!("b64.{}", fixture_passkey.credential_id)
        );
        assert_eq!(credential.rp_id, "nuri.com");
        assert_eq!(
            credential.user_handle.as_deref(),
            Some(EXPECTED_USER_HANDLE)
        );
        assert_eq!(credential.key_value, fixture_passkey.key.to_string());
        assert_eq!(credential.key_algorithm, "ECDSA");
        assert_eq!(credential.key_curve, "P-256");
        assert_eq!(credential.counter, "0");

        let state = credential.extension_state.as_ref().unwrap();
        let hmac = fixture_passkey
            .fido2_extensions
            .as_ref()
            .and_then(|extensions| extensions.hmac_credentials.as_ref())
            .unwrap();
        let expected_non_uv_seed = hmac.cred_without_uv.to_string();
        assert_eq!(state.prf_hmac_algorithm, "hmac-secret");
        assert_eq!(state.uv_hmac_seed, hmac.cred_with_uv.to_string());
        assert_eq!(
            state.non_uv_hmac_seed.as_deref(),
            Some(expected_non_uv_seed.as_str())
        );
        assert_eq!(state.key_algorithm_metadata, "ES256");
        assert!(state.cred_blob.is_none());
        assert!(state.large_blob.is_none());
    }

    fn assert_same_portable_credential(
        before: &Fido2CredentialFullView,
        after: &Fido2CredentialFullView,
    ) {
        assert_eq!(after.credential_id, before.credential_id);
        assert_eq!(after.rp_id, before.rp_id);
        assert_eq!(after.user_handle, before.user_handle);
        assert_eq!(after.key_value, before.key_value);
        assert_eq!(after.key_algorithm, before.key_algorithm);
        assert_eq!(after.key_curve, before.key_curve);
        assert_eq!(after.counter, before.counter);
        assert_eq!(after.extension_state, before.extension_state);
    }

    async fn assert_literal_prf_and_signature(
        client: &Client,
        cipher: CipherView,
        verification: Verification,
        user_verified: bool,
        expected_first: &str,
        expected_second: &str,
    ) {
        let user_interface = MockUserInterface { user_verified };
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator = Fido2Authenticator::new(client, &user_interface, &credential_store);

        let result = authenticator
            .get_assertion(request(verification))
            .await
            .unwrap();
        assert_eq!(result.credential_id, decode_b64url(EXPECTED_CREDENTIAL_ID));
        assert_eq!(result.user_handle, decode_b64url(EXPECTED_USER_HANDLE));

        let outputs = result.extensions.prf.unwrap().results;
        assert_eq!(outputs.first, decode_b64url(expected_first));
        assert_eq!(
            outputs.second.as_deref(),
            Some(decode_b64url(expected_second).as_slice())
        );

        let public_key = decode_b64url(EXPECTED_PUBLIC_KEY_SEC1);
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).unwrap();
        let signature = Signature::from_der(&result.signature).unwrap();
        let mut signed_message = result.authenticator_data;
        signed_message.extend_from_slice(&CLIENT_DATA_HASH);
        verifying_key.verify(&signed_message, &signature).unwrap();

        assert_eq!(
            credential_store.save_count(),
            0,
            "portable counter and evaluated PRF outputs must not be persisted"
        );
    }

    #[test]
    fn synthetic_cxf_fixture_matches_frozen_digest_and_public_key() {
        let digest = Sha256::digest(FIXTURE.as_bytes());
        assert_eq!(digest[..], FIXTURE_SHA256);

        let (header, passkey) = parse_fixture();
        assert_eq!(header.version.major, 1);
        assert_eq!(header.version.minor, 0);
        assert_eq!(header.accounts.len(), 1);
        assert_eq!(passkey.credential_id.to_string(), EXPECTED_CREDENTIAL_ID);
        assert_eq!(passkey.user_handle.to_string(), EXPECTED_USER_HANDLE);

        let secret_key = SecretKey::from_pkcs8_der(passkey.key.as_ref()).unwrap();
        let derived_public_key = secret_key.public_key().to_encoded_point(false);
        assert_eq!(
            derived_public_key.as_bytes(),
            decode_b64url(EXPECTED_PUBLIC_KEY_SEC1)
        );
    }

    #[tokio::test]
    async fn synthetic_cxf_identity_and_literal_prf_survive_encrypted_reload() {
        let (header, fixture_passkey) = parse_fixture();
        let account_payload = serde_json::to_string(&header.accounts[0]).unwrap();
        let import_client = create_client();
        let encrypted_cipher = import_client
            .exporters()
            .import_cxf(account_payload)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let imported_view: CipherView = import_client
            .internal
            .get_key_store()
            .decrypt(&encrypted_cipher)
            .unwrap();
        let before_reload = decrypt_fixture_credential(&import_client, &imported_view);
        assert_imported_identity(&before_reload, &fixture_passkey);

        assert_literal_prf_and_signature(
            &import_client,
            imported_view.clone(),
            Verification::Required,
            true,
            EXPECTED_UV_FIRST,
            EXPECTED_UV_SECOND,
        )
        .await;
        assert_literal_prf_and_signature(
            &import_client,
            imported_view.clone(),
            Verification::Discouraged,
            false,
            EXPECTED_NON_UV_FIRST,
            EXPECTED_NON_UV_SECOND,
        )
        .await;

        let extension_ciphertext_before_rotation = encrypted_extension_state(&imported_view);
        let mut rotated_view = imported_view;
        rotated_view
            .generate_cipher_key(
                &mut import_client.internal.get_key_store().context(),
                SymmetricKeySlotId::User,
            )
            .unwrap();
        let extension_ciphertext_after_rotation = encrypted_extension_state(&rotated_view);
        assert_ne!(
            extension_ciphertext_after_rotation, extension_ciphertext_before_rotation,
            "cipher-key rotation must re-encrypt extension state"
        );

        let encrypted_reload = import_client
            .internal
            .get_key_store()
            .encrypt(rotated_view)
            .unwrap();
        let reload_client = create_client();
        let reloaded_view: CipherView = reload_client
            .internal
            .get_key_store()
            .decrypt(&encrypted_reload)
            .unwrap();
        let after_reload = decrypt_fixture_credential(&reload_client, &reloaded_view);
        assert_imported_identity(&after_reload, &fixture_passkey);
        assert_same_portable_credential(&before_reload, &after_reload);

        assert_literal_prf_and_signature(
            &reload_client,
            reloaded_view.clone(),
            Verification::Required,
            true,
            EXPECTED_UV_FIRST,
            EXPECTED_UV_SECOND,
        )
        .await;
        assert_literal_prf_and_signature(
            &reload_client,
            reloaded_view,
            Verification::Discouraged,
            false,
            EXPECTED_NON_UV_FIRST,
            EXPECTED_NON_UV_SECOND,
        )
        .await;
    }
}
