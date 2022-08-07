use std::collections::HashMap;

use oauth2::{
    basic::{BasicClient, BasicErrorResponseType, BasicTokenType},
    http::StatusCode,
    AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    HttpRequest, HttpResponse, RedirectUrl, RefreshToken, RequestTokenError,
    RevocationErrorResponseType, Scope, StandardErrorResponse, StandardRevocableToken,
    StandardTokenIntrospectionResponse, StandardTokenResponse, TokenUrl,
};
use worker::{Request, Response};

use crate::error::{Error, Result};
use crate::fetch;

pub type OAuthResponse = StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>;

pub type OAuthClient = Client<
    StandardErrorResponse<BasicErrorResponseType>,
    OAuthResponse,
    BasicTokenType,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
>;

async fn make_req(req: HttpRequest) -> Result<HttpResponse> {
    // SAFETY: oauth2 should not provide an invalid utf8 string as a body
    let body = unsafe { std::str::from_utf8_unchecked(&req.body) };

    let mut res = fetch::RequestBuilder::new(req.method.to_string().into(), req.url.as_str())
        .set_headers(req.headers.into())
        .body(body)
        .await?;

    Ok::<_, Error>(HttpResponse {
        status_code: StatusCode::from_u16(res.status_code()).map_err(|_| Error::InternalError)?,
        headers: res.headers().into(),
        body: res.bytes().await?,
    })
}

pub struct OAuthOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub auth_url: String,
    pub token_url: Option<String>,
    pub callback_url: Option<String>,
    pub scopes: Vec<String>,
}

pub struct OAuth {
    client: OAuthClient,
    scopes: Vec<Scope>,
}

impl OAuth {
    pub fn new(opt: OAuthOptions) -> Self {
        let mut client = BasicClient::new(
            ClientId::new(opt.client_id),
            opt.client_secret.map(ClientSecret::new),
            AuthUrl::new(opt.auth_url).expect("invalid auth url"),
            opt.token_url
                .map(|token_url| TokenUrl::new(token_url).expect("invalid token url")),
        );

        if let Some(callback_url) = opt.callback_url {
            client = client
                .set_redirect_uri(RedirectUrl::new(callback_url).expect("invalid redirect url"));
        }

        Self {
            client,
            scopes: opt.scopes.into_iter().map(Scope::new).collect(),
        }
    }

    pub fn auth_grant(&self) -> Result<Response> {
        let (auth_url, csrf_token) = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("identify".to_string()))
            .add_scopes(self.scopes.clone())
            .url();

        // `Response::empty` always returns `Ok`
        let mut res = Response::empty().unwrap().with_status(302);

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

    fn validate_req_and_extract_code(req: &Request) -> Result<AuthorizationCode> {
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

        let (_, cookie_state) = cookies
            .split("; ")
            .find(|cookie| cookie.starts_with("auth_state="))
            .and_then(|cookie| cookie.split_once("="))
            .ok_or(Error::InvalidRequest)?;

        if state == cookie_state {
            Ok(AuthorizationCode::new(code.to_string()))
        } else {
            Err(Error::InvalidRequest)
        }
    }

    pub async fn exchange_code(&self, req: &Request) -> Result<OAuthResponse> {
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

    fn extract_refresh_token(req: &Request) -> Result<RefreshToken> {
        req.url()
            .map_err(|_| Error::InvalidRequest)?
            .query_pairs()
            .find(|(name, _)| name == "refresh_token")
            .map(|(_, refresh_token)| RefreshToken::new(refresh_token.to_string()))
            .ok_or(Error::InvalidRequest)
    }

    pub async fn exchange_refresh_token(&self, req: &Request) -> Result<OAuthResponse> {
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
