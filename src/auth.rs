use axum::{
    routing::{get, post},
    Router,
};
use oauth2::{ClientId, ClientSecret};
use worker::{body::Body, Env};

use crate::{
    error::Error,
    oauth::OAuthClient,
    oidc::OidcClient,
    providers::{get_provider, Provider},
    AppState,
};

pub mod authorize;
pub mod callback;
pub mod refresh;
pub mod states;
pub mod token;

pub enum AuthClient {
    OAuth2(OAuthClient),
    Oidc(OidcClient),
}

async fn get_auth_client(name: &str, env: &Env) -> Result<AuthClient, Error> {
    let provider = get_provider(name)?;

    let client_id = env
        .var(&format!("{}_CLIENT_ID", name.to_uppercase()))
        .expect("provider client ID not set")
        .to_string();
    let client_id = ClientId::new(client_id);

    let client_secret = env
        .var(&format!("{}_CLIENT_SECRET", name.to_uppercase()))
        .expect("provider client secret not set")
        .to_string();
    let client_secret = ClientSecret::new(client_secret);

    match provider {
        Provider::OAuth2(p) => Ok(AuthClient::OAuth2(OAuthClient::new(
            client_id,
            client_secret,
            p,
        ))),
        Provider::Oidc(p) => Ok(AuthClient::Oidc(
            OidcClient::new(client_id, client_secret, p).await?,
        )),
    }
}

pub fn router() -> Router<AppState, Body> {
    Router::new()
        .route("/authorize", get(authorize::oauth_authorize))
        .route("/callback", get(callback::oauth_callback))
        .route("/token", post(token::oauth_token))
        .route("/refresh", post(refresh::oauth_refresh))
}
