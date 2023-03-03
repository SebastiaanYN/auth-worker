use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use oauth2::{
    basic::{BasicErrorResponseType, BasicRequestTokenError},
    ConfigurationError, StandardErrorResponse,
};
use openidconnect::{
    ClaimsVerificationError, DiscoveryError, JsonWebTokenError, SigningError, UserInfoError,
};
use std::fmt;
use worker::kv::KvError;

#[derive(Debug)]
pub enum Error {
    OAuth2(BasicErrorResponseType, String),
    Kv(KvError),
    D1(worker::Error),
    Reqwest(reqwest::Error),
    TokenExchangeError(BasicRequestTokenError<oauth2::reqwest::Error<reqwest::Error>>),
    UserInfoError(UserInfoError<oauth2::reqwest::Error<reqwest::Error>>),
    Jwt(JsonWebTokenError),
    DiscoveryError(DiscoveryError<oauth2::reqwest::Error<reqwest::Error>>),
    MissingKeys,
    MissingIdToken,
    ClaimsVerificationError(ClaimsVerificationError),
    SigningError(SigningError),
    ConfigurationError(ConfigurationError),
    InvalidConnection,
    InvalidAccessToken,
    MissingPermission,
    TokensNotFound,
}

unsafe impl Send for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OAuth2(e, description) => write!(f, "oauth2 error {e}: {description}"),
            Self::Kv(_)
            | Self::D1(_)
            | Self::Reqwest(_)
            | Self::TokenExchangeError(_)
            | Self::UserInfoError(_)
            | Self::Jwt(_)
            | Self::DiscoveryError(_)
            | Self::MissingKeys
            | Self::MissingIdToken
            | Self::ClaimsVerificationError(_)
            | Self::SigningError(_)
            | Self::ConfigurationError(_) => write!(f, "internal error"),
            Self::InvalidConnection => write!(f, "invalid connection"),
            Self::InvalidAccessToken => write!(f, "invalid access token"),
            Self::MissingPermission => write!(f, "missing permission"),
            Self::TokensNotFound => write!(f, "tokens not found"),
        }
    }
}

impl std::error::Error for Error {}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let s = self.to_string();

        match self {
            Self::OAuth2(e, description) => (
                StatusCode::BAD_REQUEST,
                Json(StandardErrorResponse::new(e, Some(description), None)),
            )
                .into_response(),
            Self::Kv(_)
            | Self::D1(_)
            | Self::Reqwest(_)
            | Self::TokenExchangeError(_)
            | Self::UserInfoError(_)
            | Self::Jwt(_)
            | Self::DiscoveryError(_)
            | Self::MissingKeys
            | Self::MissingIdToken
            | Self::ClaimsVerificationError(_)
            | Self::SigningError(_)
            | Self::ConfigurationError(_) => (StatusCode::INTERNAL_SERVER_ERROR, s).into_response(),
            Self::InvalidConnection | Self::InvalidAccessToken | Self::MissingPermission => {
                (StatusCode::BAD_REQUEST, s).into_response()
            }
            Self::TokensNotFound => (StatusCode::NOT_FOUND, s).into_response(),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Self::Reqwest(e)
    }
}
