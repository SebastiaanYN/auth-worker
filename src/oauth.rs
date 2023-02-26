use axum::{
    routing::{get, post},
    Router,
};
use oauth2::{
    basic::{BasicClient, BasicErrorResponseType, BasicTokenType},
    AuthUrl, Client, ClientId, ClientSecret, EmptyExtraTokenFields, RedirectUrl,
    RevocationErrorResponseType, Scope, StandardErrorResponse, StandardRevocableToken,
    StandardTokenIntrospectionResponse, StandardTokenResponse, TokenUrl,
};
use worker::{body::Body, Env};

use crate::{
    error::Error,
    providers::{self, Provider},
    AppState,
};

pub mod authorize;
pub mod callback;
pub mod refresh;
pub mod states;
pub mod token;

type OAuth2Client = Client<
    StandardErrorResponse<BasicErrorResponseType>,
    StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    BasicTokenType,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
>;

pub struct OAuthClient {
    pub client: OAuth2Client,
    pub scopes: Vec<Scope>,
}

impl OAuthClient {
    pub fn new(client_id: String, client_secret: String, provider: Provider) -> Self {
        let client = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new(provider.auth_url.into()).expect("invalid auth url"),
            Some(TokenUrl::new(provider.token_url.into()).expect("invalid token url")),
        )
        .set_redirect_uri(
            RedirectUrl::new(provider.callback_url.into()).expect("invalid redirect url"),
        );

        Self {
            client,
            scopes: provider
                .scopes
                .iter()
                .map(|&scope| Scope::new(scope.into()))
                .collect(),
        }
    }
}

fn get_oauth_client(name: &str, env: &Env) -> Result<OAuthClient, Error> {
    let provider = providers::get_provider(name)?;

    let client_id = env
        .var(&format!("{}_CLIENT_ID", name.to_uppercase()))
        .expect("provider client ID not set")
        .to_string();

    let client_secret = env
        .var(&format!("{}_CLIENT_SECRET", name.to_uppercase()))
        .expect("provider client secret not set")
        .to_string();

    Ok(OAuthClient::new(client_id, client_secret, provider))
}

pub fn router() -> Router<AppState, Body> {
    Router::new()
        .route("/authorize", get(authorize::oauth_authorize))
        .route("/callback", get(callback::oauth_callback))
        .route("/token", post(token::oauth_token))
        .route("/refresh", post(refresh::oauth_refresh))
}
