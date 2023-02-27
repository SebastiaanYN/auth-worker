use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use oauth2::{
    basic::{BasicErrorResponseType, BasicRequestTokenError},
    StandardErrorResponse,
};
use openidconnect::JsonWebTokenError;
use std::fmt;
use worker::kv::KvError;

#[derive(Debug)]
pub enum Error {
    Kv(KvError),
    D1(worker::Error),
    Reqwest(reqwest::Error),
    OAuth2(BasicErrorResponseType, String),
    TokenExchangeError(BasicRequestTokenError<oauth2::reqwest::Error<reqwest::Error>>),
    Jwt(JsonWebTokenError),
    InvalidConnection,
    InvalidAccessToken,
    MissingPermission,
    TokensNotFound,
    MissingKeys,
}

unsafe impl Send for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kv(_) => write!(f, "internal error"),
            Self::D1(_) => write!(f, "internal error"),
            Self::Reqwest(_) => write!(f, "internal error"),
            Self::OAuth2(e, description) => write!(f, "oauth2 error {e}: {description}"),
            Self::TokenExchangeError(_) => write!(f, "token exchange error"),
            Self::Jwt(_) => write!(f, "internal error"),
            Self::InvalidConnection => write!(f, "invalid connection"),
            Self::InvalidAccessToken => write!(f, "invalid access token"),
            Self::MissingPermission => write!(f, "missing permission"),
            Self::TokensNotFound => write!(f, "tokens not found"),
            Self::MissingKeys => write!(f, "internal error"),
        }
    }
}

impl std::error::Error for Error {}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let s = self.to_string();

        match self {
            Self::Kv(_) => (StatusCode::INTERNAL_SERVER_ERROR, s).into_response(),
            Self::D1(_) => (StatusCode::INTERNAL_SERVER_ERROR, s).into_response(),
            Self::Reqwest(_) => (StatusCode::INTERNAL_SERVER_ERROR, s).into_response(),
            Self::OAuth2(e, description) => (
                StatusCode::BAD_REQUEST,
                Json(StandardErrorResponse::new(e, Some(description), None)),
            )
                .into_response(),
            Self::TokenExchangeError(_) => (StatusCode::INTERNAL_SERVER_ERROR, s).into_response(),
            Self::Jwt(_) => (StatusCode::INTERNAL_SERVER_ERROR, s).into_response(),
            Self::InvalidConnection => (StatusCode::BAD_REQUEST, s).into_response(),
            Self::InvalidAccessToken => (StatusCode::BAD_REQUEST, s).into_response(),
            Self::MissingPermission => (StatusCode::BAD_REQUEST, s).into_response(),
            Self::TokensNotFound => (StatusCode::NOT_FOUND, s).into_response(),
            Self::MissingKeys => (StatusCode::INTERNAL_SERVER_ERROR, s).into_response(),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Self::Reqwest(e)
    }
}
