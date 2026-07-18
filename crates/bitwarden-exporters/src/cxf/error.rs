use std::borrow::Cow;

use thiserror::Error;

use super::login::PasskeyImportError;

#[derive(Error, Debug)]
pub enum CxfError {
    #[error("JSON error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Passkey import error: {0}")]
    Passkey(String),

    #[error("Internal error: {0}")]
    Internal(Cow<'static, str>),
}

impl From<PasskeyImportError> for CxfError {
    fn from(error: PasskeyImportError) -> Self {
        Self::Passkey(error.to_string())
    }
}
