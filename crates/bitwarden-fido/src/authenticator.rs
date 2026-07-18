use std::sync::Mutex;

use bitwarden_core::Client;
use bitwarden_crypto::CryptoError;
use bitwarden_vault::{CipherError, CipherView, EncryptionContext};
use itertools::Itertools;
use passkey::{
    authenticator::{
        Authenticator, DiscoverabilitySupport, StoreInfo, UiHint, UserCheck,
        extensions::HmacSecretConfig,
    },
    types::{
        Passkey,
        ctap2::{self, Ctap2Error, StatusCode, VendorError},
    },
};
use thiserror::Error;
use tracing::error;
use zeroize::Zeroizing;

use super::{
    AAGUID, CheckUserOptions, CipherViewContainer, Fido2CredentialStore, Fido2UserInterface,
    SelectedCredential, UnknownEnumError, try_from_credential_new_view, types::*,
};
use crate::{
    Fido2CallbackError, FillCredentialError, InvalidGuidError,
    fill_with_credential_preserving_extension_state, stored_hmac_secret_from_extension_state,
    string_to_guid_bytes, try_from_credential_full,
};

#[derive(Clone, Debug)]
struct PrfEvaluationContext {
    has_fallback: bool,
    credential_ids: Vec<Vec<u8>>,
}

impl PrfEvaluationContext {
    fn from_request(request: &GetAssertionRequest) -> Option<Self> {
        let prf = request.extensions.as_ref()?.prf.as_ref()?;
        let credential_ids: Vec<Vec<u8>> = prf
            .eval_by_credential
            .as_ref()
            .map(|values| values.keys().cloned().collect())
            .unwrap_or_default();
        let has_fallback = prf.eval.is_some();

        (has_fallback || !credential_ids.is_empty()).then_some(Self {
            has_fallback,
            credential_ids,
        })
    }

    fn applies_to(&self, credential_id: &[u8]) -> bool {
        self.has_fallback
            || self
                .credential_ids
                .iter()
                .any(|candidate| candidate == credential_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrfValidationFailure {
    MissingSeedState,
    InvalidSeedState,
}

#[derive(Debug, Error)]
pub enum GetSelectedCredentialError {
    #[error("No selected credential available")]
    NoSelectedCredential,
    #[error("No fido2 credentials found")]
    NoCredentialFound,

    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum MakeCredentialError {
    #[error(transparent)]
    PublicKeyCredentialParameters(#[from] PublicKeyCredentialParametersError),
    #[error(transparent)]
    UnknownEnum(#[from] UnknownEnumError),
    #[error(transparent)]
    InvalidPrfInput(#[from] InvalidPrfInputLengthError),
    #[error("Missing attested_credential_data")]
    MissingAttestedCredentialData,
    #[error("make_credential error: {0}")]
    Other(String),
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum GetAssertionError {
    #[error(transparent)]
    UnknownEnum(#[from] UnknownEnumError),
    #[error(transparent)]
    GetSelectedCredential(#[from] GetSelectedCredentialError),
    #[error(transparent)]
    InvalidGuid(#[from] InvalidGuidError),
    #[error(transparent)]
    InvalidPrfInput(#[from] InvalidPrfInputLengthError),
    #[error("missing user")]
    MissingUser,
    /// PRF was requested but the credential has no HMAC seed state at all.
    #[error("PRF evaluation failed: no HMAC seed state present in credential")]
    PrfMissingSeedState,
    /// PRF was requested but the stored HMAC seed state could not be validated.
    #[error("PRF evaluation failed: invalid HMAC seed state")]
    PrfInvalidSeedState,
    /// PRF evaluation applied to the selected credential but no result was produced.
    #[error("PRF evaluation failed: authenticator produced no PRF output")]
    PrfOutputMissing,
    #[error("get_assertion error: {0}")]
    Other(String),
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum SilentlyDiscoverCredentialsError {
    #[error(transparent)]
    Cipher(#[from] CipherError),
    #[error(transparent)]
    InvalidGuid(#[from] InvalidGuidError),
    #[error(transparent)]
    Fido2Callback(#[from] Fido2CallbackError),
    #[error(transparent)]
    FromCipherView(#[from] Fido2CredentialAutofillViewError),
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum CredentialsForAutofillError {
    #[error(transparent)]
    Cipher(#[from] CipherError),
    #[error(transparent)]
    InvalidGuid(#[from] InvalidGuidError),
    #[error(transparent)]
    Fido2Callback(#[from] Fido2CallbackError),
    #[error(transparent)]
    FromCipherView(#[from] Fido2CredentialAutofillViewError),
}

#[allow(missing_docs)]
pub struct Fido2Authenticator<'a> {
    pub client: &'a Client,
    pub user_interface: &'a dyn Fido2UserInterface,
    pub credential_store: &'a dyn Fido2CredentialStore,

    pub(crate) selected_cipher: Mutex<Option<CipherView>>,
    pub(crate) requested_uv: Mutex<Option<UV>>,
    prf_evaluation: Mutex<Option<PrfEvaluationContext>>,
    prf_validation_failure: Mutex<Option<PrfValidationFailure>>,
}

impl<'a> Fido2Authenticator<'a> {
    #[allow(missing_docs)]
    pub fn new(
        client: &'a Client,
        user_interface: &'a dyn Fido2UserInterface,
        credential_store: &'a dyn Fido2CredentialStore,
    ) -> Fido2Authenticator<'a> {
        Fido2Authenticator {
            client,
            user_interface,
            credential_store,
            selected_cipher: Mutex::new(None),
            requested_uv: Mutex::new(None),
            prf_evaluation: Mutex::new(None),
            prf_validation_failure: Mutex::new(None),
        }
    }

    #[allow(missing_docs)]
    pub async fn make_credential(
        &mut self,
        request: MakeCredentialRequest,
    ) -> Result<MakeCredentialResult, MakeCredentialError> {
        let evaluates_prf = request
            .extensions
            .as_ref()
            .and_then(|extensions| extensions.prf.as_ref())
            .is_some_and(|prf| prf.eval.is_some());
        let effective_uv = evaluates_prf
            .then_some(UV::Required)
            .unwrap_or(request.options.uv);

        // WebAuthn PRF evaluation is only available with user verification. Store the
        // effective requirement so the UI sees the same value as the CTAP request.
        self.requested_uv
            .get_mut()
            .expect("Mutex is not poisoned")
            .replace(effective_uv);

        let mut authenticator = self.get_authenticator(true);

        let response = authenticator
            .make_credential(ctap2::make_credential::Request {
                client_data_hash: request.client_data_hash.into(),
                rp: passkey::types::ctap2::make_credential::PublicKeyCredentialRpEntity {
                    id: request.rp.id,
                    name: request.rp.name,
                },
                user: passkey::types::webauthn::PublicKeyCredentialUserEntity {
                    id: request.user.id.into(),
                    display_name: request.user.display_name,
                    name: request.user.name,
                },
                pub_key_cred_params: request
                    .pub_key_cred_params
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<_, _>>()?,
                exclude_list: request
                    .exclude_list
                    .map(|x| x.into_iter().map(TryInto::try_into).collect())
                    .transpose()?,
                // TODO(PM-30510): Even though we forward the extensions to the
                // authenticator, they will not be processed until they are
                // enabled in the authenticator configuration.
                extensions: request.extensions.map(TryInto::try_into).transpose()?,
                options: passkey::types::ctap2::make_credential::Options {
                    rk: request.options.rk,
                    up: true,
                    uv: self.convert_requested_uv(effective_uv),
                },
                pin_auth: None,
                pin_protocol: None,
            })
            .await;

        let response = match response {
            Ok(x) => x,
            Err(e) => return Err(MakeCredentialError::Other(format!("{e:?}"))),
        };

        let attestation_object = response.as_webauthn_bytes().to_vec();
        let authenticator_data = response.auth_data.to_vec();
        let attested_credential_data = response
            .auth_data
            .attested_credential_data
            .ok_or(MakeCredentialError::MissingAttestedCredentialData)?;
        let credential_id = attested_credential_data.credential_id().to_vec();
        let extensions: MakeCredentialExtensionsOutput = response.unsigned_extension_outputs.into();

        Ok(MakeCredentialResult {
            authenticator_data,
            attestation_object,
            credential_id,
            extensions,
        })
    }

    #[allow(missing_docs)]
    pub async fn get_assertion(
        &mut self,
        request: GetAssertionRequest,
    ) -> Result<GetAssertionResult, GetAssertionError> {
        let prf_evaluation = PrfEvaluationContext::from_request(&request);
        let effective_uv = prf_evaluation
            .is_some()
            .then_some(UV::Required)
            .unwrap_or(request.options.uv);

        // Per-request state must never leak from a previous assertion ceremony.
        self.selected_cipher
            .get_mut()
            .expect("Mutex is not poisoned")
            .take();
        self.prf_validation_failure
            .get_mut()
            .expect("Mutex is not poisoned")
            .take();
        *self
            .prf_evaluation
            .get_mut()
            .expect("Mutex is not poisoned") = prf_evaluation.clone();

        // WebAuthn PRF evaluation is only available with user verification. Store the
        // effective requirement so the UI sees the same value as the CTAP request.
        self.requested_uv
            .get_mut()
            .expect("Mutex is not poisoned")
            .replace(effective_uv);

        let response = {
            let mut authenticator = self.get_authenticator(false);
            authenticator
                .get_assertion(ctap2::get_assertion::Request {
                    rp_id: request.rp_id,
                    client_data_hash: request.client_data_hash.into(),
                    allow_list: request
                        .allow_list
                        .map(|l| {
                            l.into_iter()
                                .map(TryInto::try_into)
                                .collect::<Result<Vec<_>, _>>()
                        })
                        .transpose()?,
                    // TODO(PM-30510): Even though we forward the extensions to the
                    // authenticator, they will not be processed until they are
                    // enabled in the authenticator configuration.
                    extensions: request.extensions.map(TryInto::try_into).transpose()?,
                    options: passkey::types::ctap2::make_credential::Options {
                        rk: request.options.rk,
                        up: true,
                        uv: self.convert_requested_uv(effective_uv),
                    },
                    pin_auth: None,
                    pin_protocol: None,
                })
                .await
        };

        self.prf_evaluation
            .get_mut()
            .expect("Mutex is not poisoned")
            .take();

        if let Some(failure) = self
            .prf_validation_failure
            .get_mut()
            .expect("Mutex is not poisoned")
            .take()
        {
            return Err(match failure {
                PrfValidationFailure::MissingSeedState => GetAssertionError::PrfMissingSeedState,
                PrfValidationFailure::InvalidSeedState => GetAssertionError::PrfInvalidSeedState,
            });
        }

        let response = match response {
            Ok(x) => x,
            Err(e) => return Err(GetAssertionError::Other(format!("{e:?}"))),
        };

        let selected_credential = self.get_selected_credential()?;
        let authenticator_data = response.auth_data.to_vec();
        let credential_id = string_to_guid_bytes(&selected_credential.credential.credential_id)?;
        let extensions: GetAssertionExtensionsOutput = response.unsigned_extension_outputs.into();

        if prf_evaluation
            .as_ref()
            .is_some_and(|context| context.applies_to(&credential_id))
            && extensions.prf.is_none()
        {
            return Err(GetAssertionError::PrfOutputMissing);
        }

        Ok(GetAssertionResult {
            credential_id,
            authenticator_data,
            signature: response.signature.into(),
            user_handle: response
                .user
                .ok_or(GetAssertionError::MissingUser)?
                .id
                .into(),
            selected_credential,
            extensions,
        })
    }

    #[allow(missing_docs)]
    pub async fn silently_discover_credentials(
        &mut self,
        rp_id: String,
        user_handle: Option<Vec<u8>>,
    ) -> Result<Vec<Fido2CredentialAutofillView>, SilentlyDiscoverCredentialsError> {
        let key_store = self.client.internal.get_key_store();
        let result = self
            .credential_store
            .find_credentials(None, rp_id, user_handle)
            .await?;

        let mut ctx = key_store.context();
        result
            .into_iter()
            .map(
                |cipher| -> Result<Vec<Fido2CredentialAutofillView>, SilentlyDiscoverCredentialsError> {
                    Ok(Fido2CredentialAutofillView::from_cipher_view(&cipher, &mut ctx)?)
                },
            )
            .flatten_ok()
            .collect()
    }

    /// Returns all Fido2 credentials that can be used for autofill, in a view
    /// tailored for integration with OS autofill systems.
    pub async fn credentials_for_autofill(
        &mut self,
    ) -> Result<Vec<Fido2CredentialAutofillView>, CredentialsForAutofillError> {
        let all_credentials = self.credential_store.all_credentials().await?;

        all_credentials
            .into_iter()
            .map(
                |cipher| -> Result<Vec<Fido2CredentialAutofillView>, CredentialsForAutofillError> {
                    Ok(Fido2CredentialAutofillView::from_cipher_list_view(&cipher)?)
                },
            )
            .flatten_ok()
            .collect()
    }

    pub(super) fn get_authenticator(
        &self,
        create_credential: bool,
    ) -> Authenticator<CredentialStoreImpl<'_>, UserValidationMethodImpl<'_>> {
        let authenticator = Authenticator::new(
            AAGUID,
            CredentialStoreImpl {
                authenticator: self,
                create_credential,
            },
            UserValidationMethodImpl {
                authenticator: self,
            },
        );

        // This SDK surface implements WebAuthn PRF, whose hmac-secret evaluation is UV-only.
        // Imported non-UV CTAP metadata remains in the credential for portability, but this
        // configuration prevents WebAuthn PRF from ever selecting it.
        authenticator.hmac_secret(HmacSecretConfig::new_with_uv_only().enable_on_make_credential())
    }

    fn convert_requested_uv(&self, uv: UV) -> bool {
        let verification_enabled = self.user_interface.is_verification_enabled();
        match (uv, verification_enabled) {
            (UV::Preferred, true) => true,
            (UV::Preferred, false) => false,
            (UV::Required, _) => true,
            (UV::Discouraged, _) => false,
        }
    }

    fn fail_prf_validation(&self, failure: PrfValidationFailure) -> Ctap2Error {
        self.prf_validation_failure
            .lock()
            .expect("Mutex is not poisoned")
            .replace(failure);

        match failure {
            PrfValidationFailure::MissingSeedState => Ctap2Error::MissingParameter,
            PrfValidationFailure::InvalidSeedState => Ctap2Error::InvalidCredential,
        }
    }

    fn validate_selected_prf_state(&self) -> Result<(), Ctap2Error> {
        let Some(context) = self
            .prf_evaluation
            .lock()
            .expect("Mutex is not poisoned")
            .clone()
        else {
            return Ok(());
        };

        let Some(selected_cipher) = self
            .selected_cipher
            .lock()
            .expect("Mutex is not poisoned")
            .clone()
        else {
            // The normal passkey-rs no-credentials path remains authoritative.
            return Ok(());
        };

        let key_store = self.client.internal.get_key_store();
        let credentials = selected_cipher
            .get_fido2_credentials(&mut key_store.context())
            .map_err(|_| self.fail_prf_validation(PrfValidationFailure::InvalidSeedState))?;
        let credentials = Zeroizing::new(credentials);
        let credential = credentials
            .first()
            .ok_or_else(|| self.fail_prf_validation(PrfValidationFailure::InvalidSeedState))?;
        let credential_id = string_to_guid_bytes(&credential.credential_id)
            .map_err(|_| self.fail_prf_validation(PrfValidationFailure::InvalidSeedState))?;

        if !context.applies_to(&credential_id) {
            return Ok(());
        }

        stored_hmac_secret_from_extension_state(credential.extension_state.as_ref())
            .map_err(|_| self.fail_prf_validation(PrfValidationFailure::InvalidSeedState))?
            .ok_or_else(|| self.fail_prf_validation(PrfValidationFailure::MissingSeedState))?;

        Ok(())
    }

    pub(super) fn get_selected_credential(
        &self,
    ) -> Result<SelectedCredential, GetSelectedCredentialError> {
        let key_store = self.client.internal.get_key_store();

        let cipher = self
            .selected_cipher
            .lock()
            .expect("Mutex is not poisoned")
            .clone()
            .ok_or(GetSelectedCredentialError::NoSelectedCredential)?;

        let creds = cipher.decrypt_fido2_credentials(&mut key_store.context())?;

        let credential = creds
            .first()
            .ok_or(GetSelectedCredentialError::NoCredentialFound)?
            .clone();

        Ok(SelectedCredential { cipher, credential })
    }
}

pub(super) struct CredentialStoreImpl<'a> {
    authenticator: &'a Fido2Authenticator<'a>,
    create_credential: bool,
}
pub(super) struct UserValidationMethodImpl<'a> {
    authenticator: &'a Fido2Authenticator<'a>,
}

#[async_trait::async_trait]
impl passkey::authenticator::CredentialStore for CredentialStoreImpl<'_> {
    type PasskeyItem = CipherViewContainer;
    async fn find_credentials(
        &self,
        ids: Option<&[passkey::types::webauthn::PublicKeyCredentialDescriptor]>,
        rp_id: &str,
        user_handle: Option<&[u8]>,
    ) -> Result<Vec<Self::PasskeyItem>, StatusCode> {
        #[derive(Debug, Error)]
        enum InnerError {
            #[error(transparent)]
            Cipher(#[from] CipherError),
            #[error(transparent)]
            Crypto(#[from] CryptoError),
            #[error(transparent)]
            Fido2Callback(#[from] Fido2CallbackError),
        }

        // This is just a wrapper around the actual implementation to allow for ? error handling
        async fn inner(
            this: &CredentialStoreImpl<'_>,
            ids: Option<&[passkey::types::webauthn::PublicKeyCredentialDescriptor]>,
            rp_id: &str,
            user_handle: Option<&[u8]>,
        ) -> Result<Vec<CipherViewContainer>, InnerError> {
            let ids: Option<Vec<Vec<u8>>> =
                ids.map(|ids| ids.iter().map(|id| id.id.clone().into()).collect());

            let ciphers = this
                .authenticator
                .credential_store
                .find_credentials(ids, rp_id.to_string(), user_handle.map(|h| h.to_vec()))
                .await?;

            // Remove any that don't have Fido2 credentials
            let creds: Vec<_> = ciphers
                .into_iter()
                .filter(|c| {
                    c.login
                        .as_ref()
                        .and_then(|l| l.fido2_credentials.as_ref())
                        .is_some()
                })
                .collect();

            let key_store = this.authenticator.client.internal.get_key_store();

            // When using the credential for authentication we have to ask the user to pick one.
            if this.create_credential {
                Ok(creds
                    .into_iter()
                    .map(|c| CipherViewContainer::new(c, &mut key_store.context()))
                    .collect::<Result<_, _>>()?)
            } else {
                let picked = this
                    .authenticator
                    .user_interface
                    .pick_credential_for_authentication(creds)
                    .await?;

                // Store the selected credential for later use
                this.authenticator
                    .selected_cipher
                    .lock()
                    .expect("Mutex is not poisoned")
                    .replace(picked.clone());

                Ok(vec![CipherViewContainer::new(
                    picked,
                    &mut key_store.context(),
                )?])
            }
        }

        inner(self, ids, rp_id, user_handle).await.map_err(|error| {
            error!(%error, "Error finding credentials.");
            VendorError::try_from(0xF0)
                .expect("Valid vendor error code")
                .into()
        })
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        user: passkey::types::ctap2::make_credential::PublicKeyCredentialUserEntity,
        rp: passkey::types::ctap2::make_credential::PublicKeyCredentialRpEntity,
        options: passkey::types::ctap2::get_assertion::Options,
    ) -> Result<(), StatusCode> {
        #[derive(Debug, Error)]
        enum InnerError {
            #[error("Client User Id has not been set")]
            MissingUserId,
            #[error(transparent)]
            FillCredential(#[from] FillCredentialError),
            #[error(transparent)]
            Cipher(#[from] CipherError),
            #[error(transparent)]
            Crypto(#[from] CryptoError),
            #[error(transparent)]
            Fido2Callback(#[from] Fido2CallbackError),

            #[error("No selected credential available")]
            NoSelectedCredential,
        }

        // This is just a wrapper around the actual implementation to allow for ? error handling
        async fn inner(
            this: &mut CredentialStoreImpl<'_>,
            cred: Passkey,
            user: passkey::types::ctap2::make_credential::PublicKeyCredentialUserEntity,
            rp: passkey::types::ctap2::make_credential::PublicKeyCredentialRpEntity,
            options: passkey::types::ctap2::get_assertion::Options,
        ) -> Result<(), InnerError> {
            let user_id = this
                .authenticator
                .client
                .internal
                .get_user_id()
                .ok_or(InnerError::MissingUserId)?;
            let cred = try_from_credential_full(cred, user, rp, options)?;

            // Get the previously selected cipher and add the new credential to it
            let mut selected: CipherView = this
                .authenticator
                .selected_cipher
                .lock()
                .expect("Mutex is not poisoned")
                .clone()
                .ok_or(InnerError::NoSelectedCredential)?;

            let key_store = this.authenticator.client.internal.get_key_store();

            selected.set_new_fido2_credentials(&mut key_store.context(), vec![cred])?;

            // Store the updated credential for later use
            this.authenticator
                .selected_cipher
                .lock()
                .expect("Mutex is not poisoned")
                .replace(selected.clone());

            // Encrypt the updated cipher before sending it to the clients to be stored
            let encrypted = key_store.encrypt(selected)?;

            this.authenticator
                .credential_store
                .save_credential(EncryptionContext {
                    cipher: encrypted,
                    encrypted_for: user_id,
                })
                .await?;

            Ok(())
        }

        inner(self, cred, user, rp, options).await.map_err(|error| {
            error!(%error, "Error saving credential.");
            VendorError::try_from(0xF1)
                .expect("Valid vendor error code")
                .into()
        })
    }

    async fn update_credential(&mut self, cred: Passkey) -> Result<(), StatusCode> {
        #[derive(Debug, Error)]
        enum InnerError {
            #[error("Client User Id has not been set")]
            MissingUserId,
            #[error(transparent)]
            InvalidGuid(#[from] InvalidGuidError),
            #[error("Credential ID does not match selected credential")]
            CredentialIdMismatch,
            #[error("Selected full credential could not be found")]
            FullCredentialNotFound,
            #[error(transparent)]
            FillCredential(#[from] FillCredentialError),
            #[error(transparent)]
            Cipher(#[from] CipherError),
            #[error(transparent)]
            Crypto(#[from] CryptoError),
            #[error(transparent)]
            Fido2Callback(#[from] Fido2CallbackError),
            #[error(transparent)]
            GetSelectedCredential(#[from] GetSelectedCredentialError),
        }

        // This is just a wrapper around the actual implementation to allow for ? error handling
        async fn inner(
            this: &mut CredentialStoreImpl<'_>,
            cred: Passkey,
        ) -> Result<(), InnerError> {
            let user_id = this
                .authenticator
                .client
                .internal
                .get_user_id()
                .ok_or(InnerError::MissingUserId)?;
            // Get the previously selected cipher and update the credential
            let selected = this.authenticator.get_selected_credential()?;

            // Check that the provided credential ID matches the selected credential
            let new_id: &Vec<u8> = &cred.credential_id;
            let selected_id = string_to_guid_bytes(&selected.credential.credential_id)?;
            if new_id != &selected_id {
                return Err(InnerError::CredentialIdMismatch);
            }

            let key_store = this.authenticator.client.internal.get_key_store();
            let cred = {
                let existing_credentials = Zeroizing::new(
                    selected
                        .cipher
                        .get_fido2_credentials(&mut key_store.context())?,
                );
                let existing_extension_state = existing_credentials
                    .iter()
                    .find(|credential| {
                        credential.credential_id == selected.credential.credential_id
                    })
                    .ok_or(InnerError::FullCredentialNotFound)?
                    .extension_state
                    .as_ref();

                fill_with_credential_preserving_extension_state(
                    &selected.credential,
                    cred,
                    existing_extension_state,
                )?
            };

            let mut selected = selected.cipher;
            selected.set_new_fido2_credentials(&mut key_store.context(), vec![cred])?;

            // Store the updated credential for later use
            this.authenticator
                .selected_cipher
                .lock()
                .expect("Mutex is not poisoned")
                .replace(selected.clone());

            // Encrypt the updated cipher before sending it to the clients to be stored
            let encrypted = key_store.encrypt(selected)?;

            this.authenticator
                .credential_store
                .save_credential(EncryptionContext {
                    cipher: encrypted,
                    encrypted_for: user_id,
                })
                .await?;

            Ok(())
        }

        inner(self, cred).await.map_err(|error| {
            error!(%error, "Error updating credential.");
            VendorError::try_from(0xF2)
                .expect("Valid vendor error code")
                .into()
        })
    }

    async fn get_info(&self) -> StoreInfo {
        StoreInfo {
            discoverability: DiscoverabilitySupport::Full,
        }
    }
}

#[async_trait::async_trait]
impl passkey::authenticator::UserValidationMethod for UserValidationMethodImpl<'_> {
    type PasskeyItem = CipherViewContainer;

    async fn check_user<'a>(
        &self,
        hint: UiHint<'a, Self::PasskeyItem>,
        presence: bool,
        requested_verification: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        let verification = self
            .authenticator
            .requested_uv
            .lock()
            .expect("Mutex is not poisoned")
            .ok_or(Ctap2Error::UserVerificationInvalid)?;

        let options = CheckUserOptions {
            require_presence: presence,
            require_verification: verification.into(),
        };

        let result = match hint {
            UiHint::RequestNewCredential(user, rp) => {
                let new_credential = try_from_credential_new_view(user, rp)
                    .map_err(|_| Ctap2Error::InvalidCredential)?;

                let (cipher_view, user_check) = self
                    .authenticator
                    .user_interface
                    .check_user_and_pick_credential_for_creation(options, new_credential)
                    .await
                    .map_err(|_| Ctap2Error::OperationDenied)?;

                self.authenticator
                    .selected_cipher
                    .lock()
                    .expect("Mutex is not poisoned")
                    .replace(cipher_view);

                Ok(user_check)
            }
            _ => {
                self.authenticator
                    .user_interface
                    .check_user(options, map_ui_hint(hint))
                    .await
            }
        };

        let result = result.map_err(|error| {
            error!(%error, "Error checking user.");
            Ctap2Error::UserVerificationInvalid
        })?;

        // Validate the selected credential's PRF seed state before passkey-rs can
        // increment its counter, persist it, calculate extension output, or sign.
        // If requested UV failed, passkey-rs must return OperationDenied first.
        if !requested_verification || result.user_verified {
            self.authenticator.validate_selected_prf_state()?;
        }

        Ok(UserCheck {
            presence: result.user_present,
            verification: result.user_verified,
        })
    }

    fn is_presence_enabled(&self) -> bool {
        true
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        Some(self.authenticator.user_interface.is_verification_enabled())
    }
}

fn map_ui_hint(hint: UiHint<'_, CipherViewContainer>) -> UiHint<'_, CipherView> {
    use UiHint::*;
    match hint {
        InformExcludedCredentialFound(c) => InformExcludedCredentialFound(&c.cipher),
        InformNoCredentialsFound => InformNoCredentialsFound,
        RequestNewCredential(u, r) => RequestNewCredential(u, r),
        RequestExistingCredential(c) => RequestExistingCredential(&c.cipher),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use async_trait::async_trait;
    use bitwarden_core::{
        Client, UserId,
        key_management::{KeySlotIds, SymmetricKeySlotId},
    };
    use bitwarden_crypto::{KeyStoreContext, PrimitiveEncryptable, SymmetricCryptoKey};
    use bitwarden_encoding::B64Url;
    use bitwarden_vault::{
        CipherListView, CipherRepromptType, CipherType, CipherView, EncryptionContext,
        Fido2Credential, Fido2CredentialNewView, Fido2ExtensionStateView, LoginView,
    };
    use passkey::authenticator::UiHint;

    use super::{Fido2Authenticator, GetAssertionError};
    use crate::{
        CheckUserOptions, CheckUserResult, Fido2CallbackError, Fido2Client, Fido2CredentialStore,
        Fido2UserInterface, GetAssertionExtensionsInput, GetAssertionPrfInput,
        MakeCredentialExtensionsInput, MakeCredentialPrfInput, MakeCredentialRequest,
        PrfInputValues, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, Verification,
        guid_bytes_to_string, string_to_guid_bytes,
        types::{
            ClientData, GetAssertionRequest, Options, Origin, PublicKeyCredentialParameters, UV,
        },
    };

    struct MockUserInterface {
        user_verified: bool,
        creation_cipher: Option<CipherView>,
        seen_verifications: Mutex<Vec<Verification>>,
    }

    impl MockUserInterface {
        fn verified() -> Self {
            Self {
                user_verified: true,
                creation_cipher: None,
                seen_verifications: Mutex::new(Vec::new()),
            }
        }

        fn unverified() -> Self {
            Self {
                user_verified: false,
                creation_cipher: None,
                seen_verifications: Mutex::new(Vec::new()),
            }
        }

        fn for_creation(cipher: CipherView, user_verified: bool) -> Self {
            Self {
                user_verified,
                creation_cipher: Some(cipher),
                seen_verifications: Mutex::new(Vec::new()),
            }
        }

        fn assert_last_verification_required(&self) {
            assert!(matches!(
                self.seen_verifications
                    .lock()
                    .expect("Mutex is not poisoned")
                    .last(),
                Some(Verification::Required)
            ));
        }
    }

    #[async_trait]
    impl Fido2UserInterface for MockUserInterface {
        async fn check_user<'a>(
            &self,
            options: CheckUserOptions,
            _hint: UiHint<'a, CipherView>,
        ) -> Result<CheckUserResult, Fido2CallbackError> {
            self.seen_verifications
                .lock()
                .expect("Mutex is not poisoned")
                .push(options.require_verification);
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
                .ok_or(Fido2CallbackError::Unknown("no credentials".to_string()))
        }

        async fn check_user_and_pick_credential_for_creation(
            &self,
            options: CheckUserOptions,
            _new_credential: Fido2CredentialNewView,
        ) -> Result<(CipherView, CheckUserResult), Fido2CallbackError> {
            self.seen_verifications
                .lock()
                .expect("Mutex is not poisoned")
                .push(options.require_verification);
            let cipher = self.creation_cipher.clone().ok_or_else(|| {
                Fido2CallbackError::Unknown("creation cipher was not configured".to_string())
            })?;
            Ok((
                cipher,
                CheckUserResult {
                    user_present: true,
                    user_verified: self.user_verified,
                },
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

        fn saved_credentials(&self) -> Vec<EncryptionContext> {
            self.saved.lock().expect("Mutex is not poisoned").clone()
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
            Ok(vec![])
        }

        async fn save_credential(&self, cred: EncryptionContext) -> Result<(), Fido2CallbackError> {
            self.saved.lock().expect("Mutex is not poisoned").push(cred);
            Ok(())
        }
    }

    static TEST_FIDO_CREDENTIAL_ID: &str = "a36f3d35-5dae-4d07-8b24-f89e11082090";
    static TEST_FIDO_RP_ID: &str = "example.com";
    static TEST_FIDO_USER_HANDLE: &str = "YWJjZA";
    // Hardcoded P-256 private key in PKCS8 DER format for testing
    static TEST_FIDO_P256_KEY: &[u8] = &[
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20, 0x06, 0x76, 0x5e, 0x85, 0xe0, 0x7f, 0xef, 0x43, 0xaa,
        0x17, 0xe0, 0x7a, 0xd7, 0x85, 0x63, 0x01, 0x80, 0x70, 0x8c, 0x6c, 0x61, 0x43, 0x7d, 0xc3,
        0xb1, 0xe6, 0xf9, 0x09, 0x24, 0xeb, 0x1f, 0xf5, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x35,
        0x9a, 0x52, 0xf3, 0x82, 0x44, 0x66, 0x5f, 0x3f, 0xe2, 0xc4, 0x0b, 0x1c, 0x16, 0x34, 0xc5,
        0x60, 0x07, 0x3a, 0x25, 0xfe, 0x7e, 0x7f, 0x7f, 0xda, 0xd4, 0x1c, 0x36, 0x90, 0x00, 0xee,
        0xb1, 0x8e, 0x92, 0xb3, 0xac, 0x91, 0x7f, 0xb1, 0x8c, 0xa4, 0x85, 0xe7, 0x03, 0x07, 0xd1,
        0xf5, 0x5b, 0xd3, 0x7b, 0xc3, 0x56, 0x11, 0xdf, 0xbc, 0x7a, 0x97, 0x70, 0x32, 0x4b, 0x3c,
        0x84, 0x05, 0x71,
    ];

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

    async fn initialize_user(client: &Client) {
        client
            .internal
            .init_user_id(UserId::new(
                "14a55cce-9914-4b4e-83f8-870e8c480115".parse().unwrap(),
            ))
            .await
            .unwrap();
    }

    fn extension_state(non_uv_seed: Option<Vec<u8>>) -> Fido2ExtensionStateView {
        Fido2ExtensionStateView {
            prf_hmac_algorithm: "hmac-secret".to_string(),
            uv_hmac_seed: B64Url::from(vec![0x11; 32]).to_string(),
            non_uv_hmac_seed: non_uv_seed.map(|seed| B64Url::from(seed).to_string()),
            cred_blob: None,
            large_blob: None,
            key_algorithm_metadata: "ES256".to_string(),
        }
    }

    fn prf_request(
        uv: UV,
        eval: Option<PrfInputValues>,
        eval_by_credential: Option<HashMap<Vec<u8>, PrfInputValues>>,
    ) -> GetAssertionRequest {
        GetAssertionRequest {
            rp_id: TEST_FIDO_RP_ID.to_string(),
            client_data_hash: vec![0; 32],
            allow_list: None,
            options: Options { rk: false, uv },
            extensions: Some(GetAssertionExtensionsInput {
                prf: Some(GetAssertionPrfInput {
                    eval,
                    eval_by_credential,
                }),
            }),
        }
    }

    fn make_prf_request(uv: UV) -> MakeCredentialRequest {
        MakeCredentialRequest {
            client_data_hash: vec![0; 32],
            rp: PublicKeyCredentialRpEntity {
                id: TEST_FIDO_RP_ID.to_string(),
                name: Some("Example".to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: b"new-user".to_vec(),
                display_name: "New User".to_string(),
                name: "new-user@example.com".to_string(),
            },
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                ty: "public-key".to_string(),
                alg: -7,
            }],
            exclude_list: None,
            options: Options { rk: true, uv },
            extensions: Some(MakeCredentialExtensionsInput {
                prf: Some(MakeCredentialPrfInput {
                    eval: Some(PrfInputValues {
                        first: b"registration-prf".to_vec(),
                        second: None,
                        already_hashed: false,
                    }),
                }),
            }),
        }
    }

    fn expected_prf(seed: &[u8], input: &[u8]) -> Vec<u8> {
        let hashed_input =
            passkey::types::crypto::sha256(&[b"WebAuthn PRF\0".as_slice(), input].concat());
        passkey::types::crypto::hmac_sha256(seed, &hashed_input).to_vec()
    }

    fn native_prf_request(extension_name: &str, encoded_input: String) -> String {
        let mut request = serde_json::json!({
            "publicKey": {
                "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "rpId": TEST_FIDO_RP_ID,
                "userVerification": "discouraged"
            }
        });
        request["publicKey"]["extensions"][extension_name] = serde_json::json!({
            "eval": { "first": encoded_input }
        });
        request.to_string()
    }

    fn create_test_cipher(ctx: &mut KeyStoreContext<KeySlotIds>) -> CipherView {
        create_test_cipher_with_extension(ctx, None)
    }

    fn create_test_cipher_with_extension(
        ctx: &mut KeyStoreContext<KeySlotIds>,
        extension_state: Option<Fido2ExtensionStateView>,
    ) -> CipherView {
        create_test_cipher_with_extension_and_counter(ctx, extension_state, "0")
    }

    fn create_test_cipher_with_extension_and_counter(
        ctx: &mut KeyStoreContext<KeySlotIds>,
        extension_state: Option<Fido2ExtensionStateView>,
        counter: &str,
    ) -> CipherView {
        let key = SymmetricKeySlotId::User;
        let key_value = B64Url::from(TEST_FIDO_P256_KEY).to_string();

        let extension_state_enc = extension_state.map(|es| {
            let json = serde_json::to_string(&es).unwrap();
            json.encrypt(ctx, key).unwrap()
        });

        let fido2_credential = Fido2Credential {
            credential_id: TEST_FIDO_CREDENTIAL_ID.encrypt(ctx, key).unwrap(),
            key_type: "public-key".to_string().encrypt(ctx, key).unwrap(),
            key_algorithm: "ECDSA".to_string().encrypt(ctx, key).unwrap(),
            key_curve: "P-256".to_string().encrypt(ctx, key).unwrap(),
            key_value: key_value.encrypt(ctx, key).unwrap(),
            rp_id: TEST_FIDO_RP_ID.encrypt(ctx, key).unwrap(),
            user_handle: Some(TEST_FIDO_USER_HANDLE.encrypt(ctx, key).unwrap()),
            user_name: None,
            counter: counter.to_string().encrypt(ctx, key).unwrap(),
            rp_name: None,
            user_display_name: None,
            discoverable: "true".to_string().encrypt(ctx, key).unwrap(),
            creation_date: "2024-06-07T14:12:36.150Z".parse().unwrap(),
            extension_state: extension_state_enc,
        };

        CipherView {
            id: Some("c2c7e624-dcfd-4f23-af41-b177014ffcb5".parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: "Test Login".to_string(),
            notes: None,
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: None,
                password: None,
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: Some(vec![fido2_credential]),
            }),
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            bank_account: None,
            passport: None,
            drivers_license: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: false,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            attachment_decryption_failures: None,
            fields: None,
            password_history: None,
            creation_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            archived_date: None,
        }
    }

    #[tokio::test]
    async fn test_make_credential_prf_eval_overrides_discouraged_to_required() {
        let client = create_client();
        initialize_user(&client).await;
        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher(&mut ctx)
        };
        let user_interface = MockUserInterface::for_creation(cipher.clone(), true);
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);

        let result = authenticator
            .make_credential(make_prf_request(UV::Discouraged))
            .await
            .unwrap();

        user_interface.assert_last_verification_required();
        let prf = result.extensions.prf.unwrap();
        assert!(prf.enabled);
        assert_eq!(prf.results.unwrap().first.len(), 32);

        let saved = credential_store.saved_credentials();
        assert_eq!(saved.len(), 1);
        let key_store = client.internal.get_key_store();
        let saved_view: CipherView = key_store.decrypt(&saved[0].cipher).unwrap();
        let saved_credentials = saved_view
            .get_fido2_credentials(&mut key_store.context())
            .unwrap();
        let state = saved_credentials[0].extension_state.as_ref().unwrap();
        assert!(state.non_uv_hmac_seed.is_none());
    }

    #[tokio::test]
    async fn test_make_credential_prf_eval_fails_without_uv_before_persistence() {
        let client = create_client();
        initialize_user(&client).await;
        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher(&mut ctx)
        };
        let user_interface = MockUserInterface::for_creation(cipher.clone(), false);
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);

        let error = authenticator
            .make_credential(make_prf_request(UV::Discouraged))
            .await
            .err()
            .unwrap();

        user_interface.assert_last_verification_required();
        assert!(error.to_string().contains("OperationDenied"));
        assert!(credential_store.saved_credentials().is_empty());
    }

    /// UV PRF evaluation returns deterministic first and second outputs.
    #[tokio::test]
    async fn test_prf_is_evaluated_with_extension_state() {
        let client = create_client();

        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher_with_extension(&mut ctx, Some(extension_state(Some(vec![0x22; 32]))))
        };

        let user_interface = MockUserInterface::verified();
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);

        let first = b"first-input".to_vec();
        let second = b"second-input".to_vec();
        let request = prf_request(
            UV::Preferred,
            Some(PrfInputValues {
                first: first.clone(),
                second: Some(second.clone()),
                already_hashed: false,
            }),
            None,
        );

        let result = authenticator.get_assertion(request).await.unwrap();
        assert_eq!(
            TEST_FIDO_CREDENTIAL_ID,
            guid_bytes_to_string(&result.credential_id).unwrap()
        );
        let output = result.extensions.prf.unwrap().results;
        assert_eq!(output.first, expected_prf(&[0x11; 32], &first));
        assert_eq!(output.second, Some(expected_prf(&[0x11; 32], &second)));
    }

    #[tokio::test]
    async fn test_prf_already_hashed_input_preserves_apple_wallet_identity() {
        let client = create_client();
        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher_with_extension(&mut ctx, Some(extension_state(Some(vec![0x22; 32]))))
        };
        let user_interface = MockUserInterface::verified();
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);
        let raw_input = b"apple-prf-input";
        let mapped_input = passkey::types::crypto::sha256(
            &[b"WebAuthn PRF\0".as_slice(), raw_input.as_slice()].concat(),
        );
        let request = prf_request(
            UV::Discouraged,
            Some(PrfInputValues {
                first: mapped_input.to_vec(),
                second: None,
                already_hashed: true,
            }),
            None,
        );

        let result = authenticator.get_assertion(request).await.unwrap();

        user_interface.assert_last_verification_required();
        let output = result.extensions.prf.unwrap().results;
        assert_eq!(output.first, expected_prf(&[0x11; 32], raw_input));
        assert_eq!(output.second, None);
    }

    #[tokio::test]
    async fn test_prf_rejects_invalid_already_hashed_input_before_persistence() {
        let client = create_client();
        initialize_user(&client).await;
        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher_with_extension_and_counter(
                &mut ctx,
                Some(extension_state(Some(vec![0x22; 32]))),
                "1",
            )
        };
        let user_interface = MockUserInterface::verified();
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);
        let request = prf_request(
            UV::Required,
            Some(PrfInputValues {
                first: vec![0; 31],
                second: None,
                already_hashed: true,
            }),
            None,
        );

        let error = authenticator.get_assertion(request).await.err().unwrap();

        assert!(matches!(error, GetAssertionError::InvalidPrfInput(_)));
        assert!(
            user_interface
                .seen_verifications
                .lock()
                .expect("Mutex is not poisoned")
                .is_empty()
        );
        assert!(credential_store.saved_credentials().is_empty());
    }

    #[tokio::test]
    async fn test_native_client_returns_uv_prf_for_raw_and_prehashed_inputs() {
        let raw_input = b"native-client-prf";
        let mapped_input = passkey::types::crypto::sha256(
            &[b"WebAuthn PRF\0".as_slice(), raw_input.as_slice()].concat(),
        );
        let expected = expected_prf(&[0x11; 32], raw_input);

        for (extension_name, input) in [
            ("prf", raw_input.to_vec()),
            ("prfAlreadyHashed", mapped_input.to_vec()),
        ] {
            let client = create_client();
            initialize_user(&client).await;
            let cipher = {
                let mut ctx = client.internal.get_key_store().context();
                create_test_cipher_with_extension(
                    &mut ctx,
                    Some(extension_state(Some(vec![0x22; 32]))),
                )
            };
            let user_interface = MockUserInterface::verified();
            let credential_store = MockCredentialStore::new(cipher);
            let authenticator =
                Fido2Authenticator::new(&client, &user_interface, &credential_store);
            let mut native_client = Fido2Client { authenticator };

            let result = native_client
                .authenticate(
                    Origin::Web("https://example.com".to_string()),
                    native_prf_request(extension_name, B64Url::from(input).to_string()),
                    ClientData::DefaultWithCustomHash { hash: vec![0; 32] },
                )
                .await
                .unwrap();

            user_interface.assert_last_verification_required();
            let output = result
                .client_extension_results
                .prf
                .expect("native response must include PRF extension output")
                .results
                .expect("native response must include evaluated PRF values");
            assert_eq!(output.first, expected, "extension path: {extension_name}");
            assert_eq!(output.second, None);
        }
    }

    #[tokio::test]
    async fn test_native_client_prf_failure_does_not_update_counter_or_persist() {
        let client = create_client();
        initialize_user(&client).await;
        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher_with_extension_and_counter(
                &mut ctx,
                Some(extension_state(Some(vec![0x22; 32]))),
                "1",
            )
        };
        let user_interface = MockUserInterface::unverified();
        let credential_store = MockCredentialStore::new(cipher);
        let authenticator = Fido2Authenticator::new(&client, &user_interface, &credential_store);
        let mut native_client = Fido2Client { authenticator };

        let result = native_client
            .authenticate(
                Origin::Web("https://example.com".to_string()),
                native_prf_request(
                    "prf",
                    B64Url::from(b"must-not-evaluate".to_vec()).to_string(),
                ),
                ClientData::DefaultWithCustomHash { hash: vec![0; 32] },
            )
            .await;

        assert!(result.is_err());
        user_interface.assert_last_verification_required();
        assert!(credential_store.saved_credentials().is_empty());
    }

    /// A credential-specific input for another credential produces no PRF output.
    #[tokio::test]
    async fn test_prf_eval_by_credential_mismatch_produces_no_output() {
        let client = create_client();
        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher_with_extension(&mut ctx, Some(extension_state(Some(vec![0x22; 32]))))
        };

        let user_interface = MockUserInterface::verified();
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);

        let request = prf_request(
            UV::Preferred,
            None,
            Some(HashMap::from([(
                vec![0x99; 16],
                PrfInputValues {
                    first: b"not-selected".to_vec(),
                    second: None,
                    already_hashed: false,
                },
            )])),
        );

        let result = authenticator.get_assertion(request).await.unwrap();
        assert_eq!(
            TEST_FIDO_CREDENTIAL_ID,
            guid_bytes_to_string(&result.credential_id).unwrap()
        );
        assert!(
            result.extensions.prf.is_none(),
            "PRF should not be evaluated for a non-matching credential ID"
        );
    }

    /// PRF is evaluated with only the UV seed (non-UV seed is None).
    /// This covers credentials created with UV-only HMAC secret config.
    #[tokio::test]
    async fn test_prf_is_evaluated_with_uv_only_seed() {
        let client = create_client();
        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher_with_extension(&mut ctx, Some(extension_state(None)))
        };

        let user_interface = MockUserInterface::verified();
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);

        let first = b"uv-only".to_vec();
        let request = prf_request(
            UV::Preferred,
            Some(PrfInputValues {
                first: first.clone(),
                second: None,
                already_hashed: false,
            }),
            None,
        );

        let result = authenticator.get_assertion(request).await.unwrap();
        assert_eq!(
            TEST_FIDO_CREDENTIAL_ID,
            guid_bytes_to_string(&result.credential_id).unwrap()
        );
        let output = result.extensions.prf.unwrap().results;
        assert_eq!(output.first, expected_prf(&[0x11; 32], &first));
        assert_eq!(output.second, None);
    }

    /// PRF requested but credential has no extension_state → fail closed with PrfMissingSeedState.
    #[tokio::test]
    async fn test_prf_fails_closed_when_no_seed_state() {
        let client = create_client();
        initialize_user(&client).await;

        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher_with_extension_and_counter(&mut ctx, None, "1")
        };

        let user_interface = MockUserInterface::verified();
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);

        let request = prf_request(
            UV::Preferred,
            Some(PrfInputValues {
                first: b"missing-state".to_vec(),
                second: None,
                already_hashed: false,
            }),
            None,
        );

        let error = authenticator.get_assertion(request).await.err().unwrap();
        assert!(matches!(error, GetAssertionError::PrfMissingSeedState));
        assert!(
            credential_store.saved_credentials().is_empty(),
            "PRF prevalidation must fail before the signature counter is persisted"
        );
    }

    /// PRF NOT requested → no PRF output returned, even with extension_state present.
    #[tokio::test]
    async fn test_no_prf_output_when_not_requested() {
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

        let uv_seed = B64Url::from(vec![0x11u8; 32]).to_string();
        let non_uv_seed = B64Url::from(vec![0x22u8; 32]).to_string();
        let extension_state = Fido2ExtensionStateView {
            prf_hmac_algorithm: "hmac-secret".to_string(),
            uv_hmac_seed: uv_seed,
            non_uv_hmac_seed: Some(non_uv_seed),
            cred_blob: None,
            large_blob: None,
            key_algorithm_metadata: "ES256".to_string(),
        };

        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher_with_extension(&mut ctx, Some(extension_state))
        };

        let user_interface = MockUserInterface::verified();
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);

        // No PRF extension requested
        let request = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            client_data_hash: vec![0u8; 32],
            allow_list: None,
            options: Options {
                rk: false,
                uv: UV::Preferred,
            },
            extensions: None,
        };

        let result = authenticator.get_assertion(request).await.unwrap();
        assert_eq!(
            TEST_FIDO_CREDENTIAL_ID,
            guid_bytes_to_string(&result.credential_id).unwrap()
        );
        assert!(
            result.extensions.prf.is_none(),
            "PRF output should not be present when PRF was not requested"
        );
    }

    /// PRF requested with extensions but prf field is None → no PRF output, no failure.
    #[tokio::test]
    async fn test_no_prf_output_when_prf_field_is_none() {
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

        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher(&mut ctx)
        };

        let user_interface = MockUserInterface::verified();
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);

        // Extensions present but prf is None
        let request = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            client_data_hash: vec![0u8; 32],
            allow_list: None,
            options: Options {
                rk: false,
                uv: UV::Preferred,
            },
            extensions: Some(GetAssertionExtensionsInput { prf: None }),
        };

        let result = authenticator.get_assertion(request).await.unwrap();
        assert!(
            result.extensions.prf.is_none(),
            "PRF output should not be present when prf field is None"
        );
    }

    #[tokio::test]
    async fn test_prf_eval_by_credential_uses_selected_credential_input() {
        let client = create_client();
        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher_with_extension(&mut ctx, Some(extension_state(Some(vec![0x22; 32]))))
        };
        let user_interface = MockUserInterface::verified();
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);

        let selected_input = b"credential-specific".to_vec();
        let request = prf_request(
            UV::Discouraged,
            Some(PrfInputValues {
                first: b"fallback".to_vec(),
                second: None,
                already_hashed: false,
            }),
            Some(HashMap::from([(
                string_to_guid_bytes(TEST_FIDO_CREDENTIAL_ID).unwrap(),
                PrfInputValues {
                    first: selected_input.clone(),
                    second: None,
                    already_hashed: false,
                },
            )])),
        );

        let result = authenticator.get_assertion(request).await.unwrap();
        user_interface.assert_last_verification_required();
        let output = result.extensions.prf.unwrap().results;
        assert_eq!(output.first, expected_prf(&[0x11; 32], &selected_input));
        assert_eq!(output.second, None);
    }

    #[tokio::test]
    async fn test_prf_discouraged_request_is_overridden_to_uv() {
        let client = create_client();
        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher_with_extension(&mut ctx, Some(extension_state(Some(vec![0x22; 32]))))
        };
        let user_interface = MockUserInterface::verified();
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);

        let first = b"forced-uv".to_vec();
        let request = prf_request(
            UV::Discouraged,
            Some(PrfInputValues {
                first: first.clone(),
                second: None,
                already_hashed: false,
            }),
            None,
        );

        let result = authenticator.get_assertion(request).await.unwrap();
        user_interface.assert_last_verification_required();
        let output = result.extensions.prf.unwrap().results;
        assert_eq!(output.first, expected_prf(&[0x11; 32], &first));
        assert_eq!(output.second, None);
        assert_ne!(
            result.authenticator_data[32] & 0x04,
            0,
            "UV flag must be set"
        );
    }

    #[tokio::test]
    async fn test_prf_discouraged_request_fails_without_uv_before_persistence() {
        let client = create_client();
        initialize_user(&client).await;
        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher_with_extension_and_counter(
                &mut ctx,
                Some(extension_state(Some(vec![0x22; 32]))),
                "1",
            )
        };
        let user_interface = MockUserInterface::unverified();
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);
        let request = prf_request(
            UV::Discouraged,
            Some(PrfInputValues {
                first: b"uv-must-succeed".to_vec(),
                second: None,
                already_hashed: false,
            }),
            None,
        );

        let error = authenticator.get_assertion(request).await.err().unwrap();
        user_interface.assert_last_verification_required();
        assert!(
            matches!(error, GetAssertionError::Other(message) if message.contains("OperationDenied"))
        );
        assert!(credential_store.saved_credentials().is_empty());
    }

    #[tokio::test]
    async fn test_prf_invalid_seed_fails_before_persistence() {
        let client = create_client();
        initialize_user(&client).await;
        let mut invalid_state = extension_state(Some(vec![0x22; 32]));
        invalid_state.uv_hmac_seed = B64Url::from(vec![0x11; 31]).to_string();
        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher_with_extension_and_counter(&mut ctx, Some(invalid_state), "1")
        };
        let user_interface = MockUserInterface::verified();
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);
        let request = prf_request(
            UV::Preferred,
            Some(PrfInputValues {
                first: b"invalid-seed".to_vec(),
                second: None,
                already_hashed: false,
            }),
            None,
        );

        let error = authenticator.get_assertion(request).await.err().unwrap();
        assert!(matches!(error, GetAssertionError::PrfInvalidSeedState));
        assert!(credential_store.saved_credentials().is_empty());
    }

    #[tokio::test]
    async fn test_counter_update_preserves_opaque_extension_state() {
        let client = create_client();
        initialize_user(&client).await;
        let portable_credential_id = format!("b64.{}", B64Url::from(vec![0xa5; 32]));
        let mut original_state = extension_state(Some(vec![0x22; 32]));
        original_state.cred_blob = Some("opaque-cred-blob".to_string());
        original_state.large_blob = Some("opaque-large-blob".to_string());
        original_state.key_algorithm_metadata = "opaque-key-metadata".to_string();
        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            let mut cipher = create_test_cipher_with_extension_and_counter(
                &mut ctx,
                Some(original_state.clone()),
                "1",
            );
            cipher
                .login
                .as_mut()
                .unwrap()
                .fido2_credentials
                .as_mut()
                .unwrap()[0]
                .credential_id = portable_credential_id
                .encrypt(&mut ctx, SymmetricKeySlotId::User)
                .unwrap();
            cipher
        };
        let user_interface = MockUserInterface::verified();
        let credential_store = MockCredentialStore::new(cipher);
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);
        let request = prf_request(
            UV::Preferred,
            Some(PrfInputValues {
                first: b"persist-only-counter".to_vec(),
                second: None,
                already_hashed: false,
            }),
            None,
        );

        authenticator.get_assertion(request).await.unwrap();

        let saved = credential_store.saved_credentials();
        assert_eq!(saved.len(), 1);
        let key_store = client.internal.get_key_store();
        let saved_view: CipherView = key_store.decrypt(&saved[0].cipher).unwrap();
        let saved_credentials = saved_view
            .get_fido2_credentials(&mut key_store.context())
            .unwrap();
        assert_eq!(saved_credentials[0].credential_id, portable_credential_id);
        assert_eq!(saved_credentials[0].counter, "2");
        assert_eq!(
            saved_credentials[0].extension_state.as_ref(),
            Some(&original_state)
        );
    }
}
