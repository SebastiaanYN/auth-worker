use oauth2::{
    reqwest::async_http_client, AccessToken, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};
use openidconnect::{
    core::{
        CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreTokenResponse,
        CoreUserInfoClaims,
    },
    AccessTokenHash, IssuerUrl, Nonce, TokenResponse,
};
use reqwest::Url;

use crate::{error::Error, providers::OidcProvider};

pub struct OidcClient {
    pub client: CoreClient,
    pub scopes: Vec<Scope>,
}

impl OidcClient {
    pub async fn new(
        client_id: ClientId,
        client_secret: ClientSecret,
        provider: OidcProvider,
    ) -> Result<Self, Error> {
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(provider.issuer_url.into()).unwrap(),
            async_http_client,
        )
        .await
        .map_err(Error::DiscoveryError)?;

        let client = CoreClient::from_provider_metadata(metadata, client_id, Some(client_secret))
            .set_redirect_uri(
                RedirectUrl::new(format!("{}/oauth/callback", env!("DOMAIN")).into()).unwrap(),
            );

        Ok(Self {
            client,
            scopes: provider
                .scopes
                .iter()
                .map(|&scope| Scope::new(scope.into()))
                .collect(),
        })
    }

    pub fn authorize_url(&self) -> (Url, CsrfToken, Nonce, PkceCodeVerifier) {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut req = self.client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );

        for scope in self.scopes.clone() {
            req = req.add_scope(scope);
        }

        let (url, csrf, nonce) = req.set_pkce_challenge(pkce_challenge).url();
        (url, csrf, nonce, pkce_verifier)
    }

    pub async fn exchange_code(
        &self,
        code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
        nonce: &Nonce,
    ) -> Result<CoreTokenResponse, Error> {
        let res = self
            .client
            .exchange_code(code)
            .set_pkce_verifier(pkce_verifier)
            .request_async(async_http_client)
            .await
            .map_err(Error::TokenExchangeError)?;

        let id_token = res.id_token().ok_or(Error::MissingIdToken)?;
        let claims = id_token
            .claims(&self.client.id_token_verifier(), nonce)
            .map_err(Error::ClaimsVerificationError)?;

        if let Some(at_hash) = claims.access_token_hash() {
            let actual_at_hash = AccessTokenHash::from_token(
                oauth2::TokenResponse::access_token(&res),
                &id_token.signing_alg().map_err(Error::SigningError)?,
            )
            .map_err(Error::SigningError)?;

            if actual_at_hash != *at_hash {
                return Err(Error::InvalidAccessToken);
            }
        }

        Ok(res)
    }

    pub async fn user_info(&self, access_token: AccessToken) -> Result<CoreUserInfoClaims, Error> {
        self.client
            .user_info(access_token, None)
            .map_err(Error::ConfigurationError)?
            .request_async(async_http_client)
            .await
            .map_err(Error::UserInfoError)
    }
}
