use axum::{
    extract::{Query, State},
    http::Uri,
    response::{IntoResponse, Redirect},
};
use chrono::Duration;
use futures::channel::oneshot;
use oauth2::{
    basic::{BasicErrorResponseType, BasicTokenType},
    AuthorizationCode, CsrfToken, TokenResponse,
};
use openidconnect::core::{CoreIdTokenFields, CoreTokenResponse};
use serde::Deserialize;

use crate::{
    error::Error,
    gen_string, http_client, providers,
    tokens::{self, generate_access_refresh_token_set, AccessRefreshTokenSet},
    users::{upsert_user, User},
    AppState,
};

use super::{
    get_oauth_client,
    states::{AuthorizeFlowState, CodeFlowState, ConnectionTokens, TokenMetadata},
};

#[derive(Deserialize)]
pub struct CallbackRequest {
    code: AuthorizationCode,
    state: CsrfToken,
}

async fn exchange_user(
    state: &AppState,
    req: CallbackRequest,
    flow: &AuthorizeFlowState,
) -> Result<User, Error> {
    let oauth = get_oauth_client(&flow.connection, &state.env)?;

    let res = oauth
        .client
        .exchange_code(req.code)
        .request_async(oauth2::reqwest::async_http_client)
        .await
        .map_err(Error::TokenExchangeError)?;

    let user =
        providers::fetch_user(&flow.connection, http_client(), res.access_token().secret()).await?;
    upsert_user(&state.db, &user).await.map_err(Error::D1)?;

    state
        .kv
        .put(
            &format!("connection:{}:tokens", user.id),
            ConnectionTokens {
                access_token: res.access_token().clone(),
                expires_in: res
                    .expires_in()
                    .unwrap_or_else(|| Duration::weeks(1).to_std().unwrap()), // TODO: properly handle the expires
                refresh_token: res.refresh_token().cloned(),
            },
        )
        .unwrap()
        .expiration_ttl(Duration::weeks(4).num_seconds() as u64) // TODO: properly handle the expires
        .execute()
        .await
        .map_err(Error::Kv)?;

    Ok(user)
}

async fn gen_and_store_tokens(
    state: &AppState,
    flow: &AuthorizeFlowState,
    user: &User,
) -> Result<AccessRefreshTokenSet, Error> {
    let tokens = generate_access_refresh_token_set();

    state
        .kv
        .put(
            &format!("token:access:{}", tokens.access_token.secret()),
            TokenMetadata {
                client_id: user.id.clone(),
                scopes: flow.scopes.clone(),
            },
        )
        .unwrap()
        .expiration_ttl(tokens.expires_in.num_seconds() as u64)
        .execute()
        .await
        .map_err(Error::Kv)?;

    state
        .kv
        .put(
            &format!("token:refresh:{}", tokens.refresh_token.secret()),
            TokenMetadata {
                client_id: user.id.clone(),
                scopes: flow.scopes.clone(),
            },
        )
        .unwrap()
        .expiration_ttl(tokens.refresh_expires_in.num_seconds() as u64)
        .execute()
        .await
        .map_err(Error::Kv)?;

    Ok(tokens)
}

async fn oauth_callback_impl(
    state: AppState,
    req: CallbackRequest,
) -> Result<impl IntoResponse, Error> {
    let flow = state
        .kv
        .get(&format!("state:{}", req.state.secret()))
        .json::<AuthorizeFlowState>()
        .await
        .map_err(Error::Kv)?
        .ok_or(Error::OAuth2(
            BasicErrorResponseType::InvalidGrant,
            "could not find flow for the given state".into(),
        ))?;

    let user = exchange_user(&state, req, &flow).await?;
    let access_refresh_tokens = gen_and_store_tokens(&state, &flow, &user).await?;

    let code = AuthorizationCode::new(gen_string(16));

    let id_token = tokens::id_token(
        &state,
        &flow.client_id,
        &code,
        user,
        &access_refresh_tokens.access_token,
    )
    .await?;

    let mut reply = CoreTokenResponse::new(
        access_refresh_tokens.access_token,
        BasicTokenType::Bearer,
        CoreIdTokenFields::new(Some(id_token), oauth2::EmptyExtraTokenFields {}),
    );
    reply.set_refresh_token(Some(access_refresh_tokens.refresh_token));
    reply.set_expires_in(Some(&access_refresh_tokens.expires_in.to_std().unwrap()));
    reply.set_scopes(Some(Vec::from_iter(flow.scopes)));

    let uri = format!(
        "{}?code={}&state={}",
        flow.redirect_uri,
        code.secret(),
        flow.state.secret(),
    )
    .parse::<Uri>()
    .map_err(|_| {
        Error::OAuth2(
            BasicErrorResponseType::InvalidRequest,
            "redirect_uri is malformed".into(),
        )
    })?;

    state
        .kv
        .put(
            &format!("code:{}", code.secret()),
            CodeFlowState {
                reply,
                client_id: flow.client_id,
                redirect_uri: flow.redirect_uri,
            },
        )
        .unwrap()
        .expiration_ttl(60)
        .execute()
        .await
        .map_err(Error::Kv)?;

    Ok(Redirect::temporary(&uri.to_string()))
}

pub async fn oauth_callback(
    State(state): State<AppState>,
    Query(req): Query<CallbackRequest>,
) -> impl IntoResponse {
    let (tx, rx) = oneshot::channel();

    wasm_bindgen_futures::spawn_local(async move {
        let res = oauth_callback_impl(state, req).await;
        tx.send(res).map_err(|_| ()).unwrap();
    });

    rx.await.unwrap()
}
