use oauth2::{
    basic::{BasicClient, BasicTokenResponse},
    reqwest::async_http_client,
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenUrl,
};
use reqwest::Url;

use crate::{error::Error, providers::OAuth2Provider};

pub struct OAuthClient {
    pub client: BasicClient,
    pub scopes: Vec<Scope>,
}

impl OAuthClient {
    pub fn new(client_id: ClientId, client_secret: ClientSecret, provider: OAuth2Provider) -> Self {
        let client = BasicClient::new(
            client_id,
            Some(client_secret),
            AuthUrl::new(provider.auth_url.into()).expect("invalid auth url"),
            Some(TokenUrl::new(provider.token_url.into()).expect("invalid token url")),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/oauth/callback", env!("DOMAIN")).into()).unwrap(),
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

    pub fn authorize_url(&self) -> (Url, CsrfToken, PkceCodeVerifier) {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (url, csrf) = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(self.scopes.clone())
            .set_pkce_challenge(pkce_challenge)
            .url();

        (url, csrf, pkce_verifier)
    }

    pub async fn exchange_code(
        &self,
        code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
    ) -> Result<BasicTokenResponse, Error> {
        self.client
            .exchange_code(code)
            .set_pkce_verifier(pkce_verifier)
            .request_async(async_http_client)
            .await
            .map_err(Error::TokenExchangeError)
    }
}
