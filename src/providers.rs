use oauth2::AccessToken;
use reqwest::Client;

use crate::{error::Error, users::User};

mod discord;
mod github;

pub struct OAuth2Provider {
    pub auth_url: &'static str,
    pub token_url: &'static str,
    pub scopes: &'static [&'static str],
}

pub struct OidcProvider {
    pub issuer_url: &'static str,
    pub scopes: &'static [&'static str],
}

#[allow(unused)]
pub enum Provider {
    OAuth2(OAuth2Provider),
    Oidc(OidcProvider),
}

include!(concat!(env!("OUT_DIR"), "/providers.rs"));
