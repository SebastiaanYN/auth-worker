use axum::{extract::State, response::IntoResponse, Form, Json};
use futures::channel::oneshot;
use oauth2::{basic::BasicErrorResponseType, ClientId, ClientSecret, UserCode};
use openidconnect::core::CoreGrantType;
use serde::Deserialize;

use crate::{applications, error::Error, AppState};

use super::states::CodeFlowState;

#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: CoreGrantType,
    client_id: ClientId,
    client_secret: ClientSecret,
    code: UserCode,
    redirect_uri: String,
}

async fn oauth_token_impl(state: AppState, req: TokenRequest) -> impl IntoResponse {
    if req.grant_type != CoreGrantType::AuthorizationCode {
        return Err(Error::OAuth2(
            BasicErrorResponseType::UnsupportedGrantType,
            "expected grant_type authorization_code".into(),
        ));
    }

    let valid_creds =
        applications::verify_client_creds(&state.db, &req.client_id, &req.client_secret).await;

    if !valid_creds {
        return Err(Error::OAuth2(
            BasicErrorResponseType::InvalidClient,
            "invalid client credentials".into(),
        ));
    }

    let flow = state
        .kv
        .get(&format!("code:{}", req.code.secret()))
        .json::<CodeFlowState>()
        .await
        .map_err(Error::Kv)?
        .ok_or(Error::OAuth2(
            BasicErrorResponseType::InvalidGrant,
            "invalid code".into(),
        ))?;

    if req.client_id != flow.client_id {
        return Err(Error::OAuth2(
            BasicErrorResponseType::InvalidGrant,
            "client_id does not belong to this flow".into(),
        ));
    }

    if req.redirect_uri != flow.redirect_uri {
        return Err(Error::OAuth2(
            BasicErrorResponseType::InvalidGrant,
            "redirect_uri does not belong to this flow".into(),
        ));
    }

    Ok(Json(flow.reply))
}

pub async fn oauth_token(
    State(state): State<AppState>,
    Form(req): Form<TokenRequest>,
) -> impl IntoResponse {
    let (tx, rx) = oneshot::channel();

    wasm_bindgen_futures::spawn_local(async move {
        let res = oauth_token_impl(state, req).await;
        tx.send(res).map_err(|_| ()).unwrap();
    });

    rx.await.unwrap()
}
