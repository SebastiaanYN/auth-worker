use serde::Serialize;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    InternalError,
    InvalidHeader,
    InvalidRequest,
    InvalidAuthState,
    InvalidProvider,
    Serde(serde_json::Error),
    Worker(worker::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InternalError => write!(f, "internal error"),
            Error::InvalidHeader => write!(f, "invalid header"),
            Error::InvalidRequest => write!(f, "invalid request"),
            Error::InvalidAuthState => write!(f, "invalid auth state"),
            Error::InvalidProvider => write!(f, "invalid provider"),
            Error::Serde(err) => err.fmt(f),
            Error::Worker(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

impl From<Error> for worker::Result<worker::Response> {
    fn from(error: Error) -> Self {
        Ok(worker::Response::from_json(&ErrorResponse {
            error: error.to_string(),
        })
        .unwrap()
        .with_status(400))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
