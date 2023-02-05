use oauth2::TokenResponse;
use worker::*;

mod error;
mod fetch;
mod oauth;
mod providers;
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
        .expect("provider client id not set")
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
    let res = oauth_client(provider, ctx)?.exchange_code(&req).await?;

    providers::fetch_user(provider, res.access_token().secret())
        .await
        .and_then(|user| Response::from_json(&user).map_err(|_| Error::InternalError))
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
        .run(req, env)
        .await
}
