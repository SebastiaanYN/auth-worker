use std::collections::HashMap;

use oauth2::{
    basic::{BasicClient, BasicErrorResponseType, BasicTokenType},
    http::StatusCode,
    AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    RedirectUrl, RefreshToken, RequestTokenError, RevocationErrorResponseType, Scope,
    StandardErrorResponse, StandardRevocableToken, StandardTokenIntrospectionResponse,
    StandardTokenResponse, TokenUrl,
};

use crate::{
    error::{Error, Result},
    fetch,
    providers::Provider,
};

pub type OAuthResponse = StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>;

pub type OAuthClient = Client<
    StandardErrorResponse<BasicErrorResponseType>,
    OAuthResponse,
    BasicTokenType,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
>;

async fn make_req(req: oauth2::HttpRequest) -> Result<oauth2::HttpResponse> {
    // SAFETY: oauth2 should not provide an invalid utf8 string as a body
    let body = unsafe { std::str::from_utf8_unchecked(&req.body) };

    let mut res = fetch::RequestBuilder::new(req.method.to_string().into(), req.url.as_str())
        .set_headers(req.headers.into())
        .body(body)
        .await?;

    Ok::<_, Error>(oauth2::HttpResponse {
        status_code: StatusCode::from_u16(res.status_code()).map_err(|_| Error::InternalError)?,
        headers: res.headers().into(),
        body: res.bytes().await?,
    })
}

pub struct OAuth {
    client: OAuthClient,
    scopes: Vec<Scope>,
}

impl OAuth {
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

    /// Start the authorization grant flow. Generates a [`worker::Response`] that redirects to the authorization URL.
    pub fn auth_grant(&self) -> Result<worker::Response> {
        let (auth_url, csrf_token) = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("identify".to_string()))
            .add_scopes(self.scopes.clone())
            .url();

        // `Response::empty` always returns `Ok`
        let mut res = worker::Response::empty().unwrap().with_status(302);

        res.headers_mut()
            .set(
                "Set-Cookie",
                &format!("auth_state={}; HttpOnly; Secure", csrf_token.secret()),
            )
            .map_err(|_| Error::InternalError)?;

        res.headers_mut()
            .set("Location", auth_url.as_str())
            .map_err(|_| Error::InternalError)?;

        Ok(res)
    }

    fn validate_req_and_extract_code(req: &worker::Request) -> Result<AuthorizationCode> {
        let url = req.url().map_err(|_| Error::InternalError)?;
        let query = url.query_pairs().collect::<HashMap<_, _>>();

        let code = query.get("code").ok_or(Error::InvalidRequest)?;
        let state = query.get("state").ok_or(Error::InvalidRequest)?;

        let cookies = req
            .headers()
            .get("Cookie")
            .ok()
            .flatten()
            .ok_or(Error::InvalidRequest)?;

        // Extract auth state from the cookies
        let (_, cookie_state) = cookies
            .split("; ")
            .find(|cookie| cookie.starts_with("auth_state="))
            .and_then(|cookie| cookie.split_once("="))
            .ok_or(Error::InvalidRequest)?;

        // Verify the auth state is correct
        if state == cookie_state {
            Ok(AuthorizationCode::new(code.to_string()))
        } else {
            Err(Error::InvalidAuthState)
        }
    }

    /// Exchange authorization code for access and refresh tokens.
    pub async fn exchange_code(&self, req: &worker::Request) -> Result<OAuthResponse> {
        let code = OAuth::validate_req_and_extract_code(&req)?;

        self.client
            .exchange_code(code)
            .request_async(make_req)
            .await
            .map_err(|err| match err {
                RequestTokenError::Request(err) => err,
                _ => Error::InternalError,
            })
    }

    fn extract_refresh_token(req: &worker::Request) -> Result<RefreshToken> {
        req.url()
            .map_err(|_| Error::InvalidRequest)?
            .query_pairs()
            .find(|(name, _)| name == "refresh_token")
            .map(|(_, refresh_token)| RefreshToken::new(refresh_token.to_string()))
            .ok_or(Error::InvalidRequest)
    }

    /// Exchange refresh tokens for new access and refresh tokens.
    pub async fn exchange_refresh_token(&self, req: &worker::Request) -> Result<OAuthResponse> {
        let refresh_token = OAuth::extract_refresh_token(&req)?;

        self.client
            .exchange_refresh_token(&refresh_token)
            .request_async(make_req)
            .await
            .map_err(|err| match err {
                RequestTokenError::Request(err) => err,
                _ => Error::InternalError,
            })
    }
}
