use passkey::client::WebauthnError;
use passkey::types::webauthn::{
    AuthenticationExtensionsClientInputs, AuthenticationExtensionsPrfInputs,
    UserVerificationRequirement,
};
use thiserror::Error;

use super::{
    Fido2Authenticator, PublicKeyCredentialAuthenticatorAssertionResponse,
    PublicKeyCredentialAuthenticatorAttestationResponse,
    authenticator::GetSelectedCredentialError,
    get_string_name_from_enum,
    types::{
        AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, ClientData,
        ClientExtensionResults, CredPropsResult, Origin,
    },
};
use crate::types::InvalidOriginError;

fn selected_prf_input(
    extensions: Option<&AuthenticationExtensionsClientInputs>,
) -> Option<&AuthenticationExtensionsPrfInputs> {
    extensions.and_then(|extensions| {
        extensions
            .prf
            .as_ref()
            .or(extensions.prf_already_hashed.as_ref())
    })
}

fn registration_evaluates_prf(extensions: Option<&AuthenticationExtensionsClientInputs>) -> bool {
    selected_prf_input(extensions).is_some_and(|prf| prf.eval.is_some())
}

fn authentication_evaluates_prf(extensions: Option<&AuthenticationExtensionsClientInputs>) -> bool {
    selected_prf_input(extensions).is_some_and(|prf| {
        prf.eval.is_some()
            || prf
                .eval_by_credential
                .as_ref()
                .is_some_and(|values| !values.is_empty())
    })
}

fn enforce_registration_prf_uv(request: &mut passkey::types::webauthn::CredentialCreationOptions) {
    if registration_evaluates_prf(request.public_key.extensions.as_ref()) {
        request
            .public_key
            .authenticator_selection
            .get_or_insert_with(Default::default)
            .user_verification = UserVerificationRequirement::Required;
    }
}

fn enforce_authentication_prf_uv(request: &mut passkey::types::webauthn::CredentialRequestOptions) {
    if authentication_evaluates_prf(request.public_key.extensions.as_ref()) {
        request.public_key.user_verification = UserVerificationRequirement::Required;
    }
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum Fido2ClientError {
    #[error(transparent)]
    InvalidOrigin(#[from] InvalidOriginError),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    GetSelectedCredential(#[from] GetSelectedCredentialError),

    #[error("Webauthn error: {0:?}")]
    Webauthn(WebauthnError),
}

impl From<WebauthnError> for Fido2ClientError {
    fn from(e: WebauthnError) -> Self {
        Self::Webauthn(e)
    }
}

#[allow(missing_docs)]
pub struct Fido2Client<'a> {
    pub authenticator: Fido2Authenticator<'a>,
}

impl Fido2Client<'_> {
    #[allow(missing_docs)]
    pub async fn register(
        &mut self,
        origin: Origin,
        request: String,
        client_data: ClientData,
    ) -> Result<PublicKeyCredentialAuthenticatorAttestationResponse, Fido2ClientError> {
        let origin: passkey::client::Origin = origin.try_into()?;
        let mut request: passkey::types::webauthn::CredentialCreationOptions =
            serde_json::from_str(&request)?;

        enforce_registration_prf_uv(&mut request);

        // Insert the received UV to be able to return it later in check_user
        let uv = request
            .public_key
            .authenticator_selection
            .as_ref()
            .map(|s| s.user_verification.into());
        *self
            .authenticator
            .requested_uv
            .get_mut()
            .expect("Mutex is not poisoned") = uv;

        let rp_id = request.public_key.rp.id.clone();

        let mut client = passkey::client::Client::new(self.authenticator.get_authenticator(true));
        let result = client.register(origin, request, client_data).await?;

        Ok(PublicKeyCredentialAuthenticatorAttestationResponse {
            id: result.id,
            raw_id: result.raw_id.into(),
            ty: get_string_name_from_enum(result.ty)?,
            authenticator_attachment: result
                .authenticator_attachment
                .map(get_string_name_from_enum)
                .transpose()?,
            client_extension_results: ClientExtensionResults {
                cred_props: result.client_extension_results.cred_props.map(Into::into),
            },
            response: AuthenticatorAttestationResponse {
                client_data_json: result.response.client_data_json.into(),
                authenticator_data: result.response.authenticator_data.into(),
                public_key: result.response.public_key.map(|x| x.into()),
                public_key_algorithm: result.response.public_key_algorithm,
                attestation_object: result.response.attestation_object.into(),
                transports: if rp_id.unwrap_or_default() == "https://google.com" {
                    Some(vec!["internal".to_string(), "usb".to_string()])
                } else {
                    Some(vec!["internal".to_string()])
                },
            },
            selected_credential: self.authenticator.get_selected_credential()?,
        })
    }

    #[allow(missing_docs)]
    pub async fn authenticate(
        &mut self,
        origin: Origin,
        request: String,
        client_data: ClientData,
    ) -> Result<PublicKeyCredentialAuthenticatorAssertionResponse, Fido2ClientError> {
        let origin: passkey::client::Origin = origin.try_into()?;
        let mut request: passkey::types::webauthn::CredentialRequestOptions =
            serde_json::from_str(&request)?;

        enforce_authentication_prf_uv(&mut request);

        // Insert the received UV to be able to return it later in check_user
        let uv = request.public_key.user_verification.into();
        self.authenticator
            .requested_uv
            .get_mut()
            .expect("Mutex is not poisoned")
            .replace(uv);

        let mut client = passkey::client::Client::new(self.authenticator.get_authenticator(false));
        let result = client.authenticate(origin, request, client_data).await?;

        Ok(PublicKeyCredentialAuthenticatorAssertionResponse {
            id: result.id,
            raw_id: result.raw_id.into(),
            ty: get_string_name_from_enum(result.ty)?,

            authenticator_attachment: result
                .authenticator_attachment
                .map(get_string_name_from_enum)
                .transpose()?,
            client_extension_results: ClientExtensionResults {
                cred_props: result
                    .client_extension_results
                    .cred_props
                    .map(|c| CredPropsResult { rk: c.discoverable }),
            },
            response: AuthenticatorAssertionResponse {
                client_data_json: result.response.client_data_json.into(),
                authenticator_data: result.response.authenticator_data.into(),
                signature: result.response.signature.into(),
                user_handle: result.response.user_handle.unwrap_or_default().into(),
            },
            selected_credential: self.authenticator.get_selected_credential()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use passkey::types::webauthn::{
        CredentialCreationOptions, CredentialRequestOptions, UserVerificationRequirement,
    };
    use serde_json::json;

    use super::{enforce_authentication_prf_uv, enforce_registration_prf_uv};

    fn registration_json(extension_name: Option<&str>, with_eval: bool) -> String {
        let mut value = json!({
            "publicKey": {
                "rp": { "id": "nuri.com", "name": "Nuri" },
                "user": {
                    "id": "AQIDBA",
                    "name": "emin@nuri.com",
                    "displayName": "Emin"
                },
                "challenge": "BQYHCA",
                "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
                "authenticatorSelection": { "userVerification": "discouraged" }
            }
        });
        if let Some(extension_name) = extension_name {
            let prf = if with_eval {
                json!({ "eval": { "first": "bm90LWhhc2hlZC1oZXJl" } })
            } else {
                json!({})
            };
            value["publicKey"]["extensions"][extension_name] = prf;
        }
        value.to_string()
    }

    fn authentication_json(extension_name: Option<&str>, with_eval: bool) -> String {
        let mut value = json!({
            "publicKey": {
                "challenge": "BQYHCA",
                "rpId": "nuri.com",
                "userVerification": "discouraged"
            }
        });
        if let Some(extension_name) = extension_name {
            let prf = if with_eval {
                json!({ "eval": { "first": "bm90LWhhc2hlZC1oZXJl" } })
            } else {
                json!({})
            };
            value["publicKey"]["extensions"][extension_name] = prf;
        }
        value.to_string()
    }

    #[test]
    fn registration_json_prf_evaluations_force_required_uv() {
        for extension_name in ["prf", "prfAlreadyHashed"] {
            let mut request: CredentialCreationOptions =
                serde_json::from_str(&registration_json(Some(extension_name), true)).unwrap();

            enforce_registration_prf_uv(&mut request);

            assert_eq!(
                request
                    .public_key
                    .authenticator_selection
                    .unwrap()
                    .user_verification,
                UserVerificationRequirement::Required
            );
        }
    }

    #[test]
    fn authentication_json_prf_evaluations_force_required_uv() {
        for extension_name in ["prf", "prfAlreadyHashed"] {
            let mut request: CredentialRequestOptions =
                serde_json::from_str(&authentication_json(Some(extension_name), true)).unwrap();

            enforce_authentication_prf_uv(&mut request);

            assert_eq!(
                request.public_key.user_verification,
                UserVerificationRequirement::Required
            );
        }
    }

    #[test]
    fn authentication_json_eval_by_credential_forces_required_uv() {
        for extension_name in ["prf", "prfAlreadyHashed"] {
            let mut value: serde_json::Value =
                serde_json::from_str(&authentication_json(None, false)).unwrap();
            value["publicKey"]["allowCredentials"] =
                json!([{ "type": "public-key", "id": "AQIDBA" }]);
            value["publicKey"]["extensions"][extension_name] = json!({
                "evalByCredential": {
                    "AQIDBA": { "first": "bm90LWhhc2hlZC1oZXJl" }
                }
            });
            let mut request: CredentialRequestOptions = serde_json::from_value(value).unwrap();

            enforce_authentication_prf_uv(&mut request);

            assert_eq!(
                request.public_key.user_verification,
                UserVerificationRequirement::Required
            );
        }
    }

    #[test]
    fn probe_only_and_absent_prf_leave_uv_unchanged() {
        for extension_name in [Some("prf"), Some("prfAlreadyHashed"), None] {
            let mut registration: CredentialCreationOptions =
                serde_json::from_str(&registration_json(extension_name, false)).unwrap();
            enforce_registration_prf_uv(&mut registration);
            assert_eq!(
                registration
                    .public_key
                    .authenticator_selection
                    .unwrap()
                    .user_verification,
                UserVerificationRequirement::Discouraged
            );

            let mut authentication: CredentialRequestOptions =
                serde_json::from_str(&authentication_json(extension_name, false)).unwrap();
            enforce_authentication_prf_uv(&mut authentication);
            assert_eq!(
                authentication.public_key.user_verification,
                UserVerificationRequirement::Discouraged
            );
        }
    }
}
