use application::CreateApplication;
use rand::distributions::DistString;
use serde::Deserialize;
use worker::*;

mod application;
mod d1;
mod error;
mod fetch;
mod oauth;
mod providers;
mod sql;
mod tokens;
mod user;
mod utils;

use error::{Error, Result};
use oauth::OAuth;

fn log_request(req: &Request) {
    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        req.cf().coordinates().unwrap_or_default(),
        req.cf().region().unwrap_or("unknown region".into())
    );
}

fn oauth_client(name: &str, ctx: &RouteContext<()>) -> Result<OAuth> {
    let provider = providers::get_provider(name)?;

    let client_id = ctx
        .var(&format!("{}_CLIENT_ID", name.to_uppercase()))
        .expect("provider client ID not set")
        .to_string();

    let client_secret = ctx
        .var(&format!("{}_CLIENT_SECRET", name.to_uppercase()))
        .expect("provider client secret not set")
        .to_string();

    Ok(OAuth::new(client_id, client_secret, provider))
}

fn handle_oauth_grant(name: &str, ctx: &RouteContext<()>) -> Result<Response> {
    oauth_client(name, ctx)?.auth_grant()
}

async fn handle_oauth_callback(
    provider: &str,
    req: &Request,
    ctx: &RouteContext<()>,
) -> Result<Response> {
    use oauth2::TokenResponse;

    let res = oauth_client(provider, ctx)?.exchange_code(&req).await?;
    let user = providers::fetch_user(provider, res.access_token().secret()).await?;

    let db = d1::binding(&ctx.env, "DB").expect("DB does not exist");
    sql::upsert_user(&db, &user)
        .await
        .map_err(|_| Error::InternalError)?;

    let rsa_priv_pem = ctx
        .var("PRIV_KEY")
        .expect("RSA private key not set")
        .to_string();
    let id_token =
        tokens::id_token(user.clone(), &rsa_priv_pem, res.access_token()).map_err(|e| {
            console_error!("{e}");
            Error::InternalError
        })?;

    let mut reply = openidconnect::core::CoreTokenResponse::new(
        res.access_token().clone(),
        res.token_type().clone(),
        openidconnect::core::CoreIdTokenFields::new(
            Some(id_token),
            oauth2::EmptyExtraTokenFields {},
        ),
    );
    reply.set_refresh_token(res.refresh_token().cloned());
    reply.set_expires_in(res.expires_in().as_ref());
    reply.set_scopes(res.scopes().cloned());

    let code = rand::distributions::Alphanumeric.sample_string(&mut rand::rngs::OsRng, 16);

    let kv = ctx.kv("KV").expect("KV does not exist");
    kv.put(&code, &reply)
        .map_err(|e| {
            console_error!("{e}");
            Error::InternalError
        })?
        .expiration_ttl(60)
        .execute()
        .await
        .map_err(|e| {
            console_error!("{e}");
            Error::InternalError
        })?;

    Response::from_json(&code).map_err(|e| {
        console_error!("{e}");
        Error::InternalError
    })
}

async fn handle_oauth_refresh(
    provider: &str,
    req: &Request,
    ctx: &RouteContext<()>,
) -> Result<Response> {
    oauth_client(provider, ctx)?
        .exchange_refresh_token(&req)
        .await
        .and_then(|res| Response::from_json(&res).map_err(|_| Error::InternalError))
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> worker::Result<Response> {
    log_request(&req);
    utils::set_panic_hook();

    Router::new()
        .get("/login", |_, _| {
            Response::from_html(include_str!(concat!(env!("OUT_DIR"), "/login.html")))
        })
        .post_async("/application", |mut req, ctx| async move {
            let data = req.json::<CreateApplication>().await?;
            let db = d1::binding(&ctx.env, "DB")?;

            if let Some(res) = application::create_application(&db, &data).await {
                Response::from_json(&res)
            } else {
                Response::empty()
            }
        })
        .get("/oauth/:provider", |_, ctx| {
            if let Some(provider) = ctx.param("provider") {
                handle_oauth_grant(provider, &ctx).or_else(Into::into)
            } else {
                Response::empty()
            }
        })
        .get_async("/oauth/:provider/callback", |req, ctx| async move {
            if let Some(provider) = ctx.param("provider") {
                handle_oauth_callback(provider, &req, &ctx)
                    .await
                    .or_else(Into::into)
            } else {
                Response::empty()
            }
        })
        .get_async("/oauth/:provider/refresh", |req, ctx| async move {
            if let Some(provider) = ctx.param("provider") {
                handle_oauth_refresh(provider, &req, &ctx)
                    .await
                    .or_else(Into::into)
            } else {
                Response::empty()
            }
        })
        .get_async("/oauth/authorize", |req, _| async move {
            #[derive(Deserialize)]
            struct AuthorizeRequest {
                response_type: String,
                client_id: String,
                redirect_uri: String,
                scope: Option<String>,
                state: String,
            }

            let Ok(auth_req) = serde_urlencoded::from_str::<AuthorizeRequest>(&req.url()?.query().unwrap_or("")) else { return Response::empty() };

            if auth_req.response_type != "code" {
                return Response::empty();
            }

            // let url = Url::parse_with_params(&format!("{}/login", std::env!("DOMAIN")), [
            //     ("response_type", auth_req.response_type),
            //     ("client_id", auth_req.client_id),
            //     ("redirect_uri", auth_req.redirect_uri),
            //     ("scope", auth_req.scope.unwrap_or_else(String::new)),
            //     ("state", auth_req.state),
            // ])?;

            Response::from_html(include_str!(concat!(env!("OUT_DIR"), "/login.html")))
        })
        .post_async("/oauth/token", |mut req, ctx| async move {
            let valid_content_type = req
                .headers()
                .get("content-type")?
                .map(|ty| ty == "application/x-www-form-urlencoded")
                .unwrap_or(false);
            if !valid_content_type {
                return Response::empty();
            }

            #[derive(Deserialize)]
            struct AccessTokenRequest {
                grant_type: String,
                client_id: String,
                client_secret: String,
                code: String,
                redirect_uri: String,
            }

            let body = req.text().await?;
            let Ok(token_req) = serde_urlencoded::from_str::<AccessTokenRequest>(&body) else { return Response::empty() };

            if token_req.grant_type != "authorization_code" {
                return Response::empty();
            }

            let db = d1::binding(&ctx.env, "DB").expect("DB does not exist");
            if !application::verify_client_creds(&db, &token_req.client_id, &token_req.client_secret).await {
                return Response::empty();
            }

            let kv = ctx.kv("KV").expect("KV does not exist");
            let res = kv
                .get(&token_req.code)
                .json::<openidconnect::core::CoreTokenResponse>()
                .await?;

            if let Some(res) = res {
                Response::from_json(&res)
            } else {
                Response::empty()
            }
        })
        .get("/.well-known/jwks.json", |_, ctx| {
            let rsa_priv_pem = ctx
                .var("PRIV_KEY")
                .expect("RSA private key not set")
                .to_string();

            Response::from_json(&tokens::create_jwks(&rsa_priv_pem))
        })
        .run(req, env)
        .await
}
