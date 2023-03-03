use std::{collections::HashSet, fmt::Debug};

use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::Duration;
use futures::channel::oneshot;
use oauth2::{basic::BasicErrorResponseType, ClientId, CsrfToken, ResponseType, Scope};
use serde::{Deserialize, Serialize};

use crate::{applications::get_scopes, error::Error, AppState};

use super::{
    get_auth_client,
    states::{AuthorizeFlowState, AuthorizeFlowStateType},
    AuthClient,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    pub connection: Option<String>,
    pub response_type: ResponseType,
    pub client_id: ClientId,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: CsrfToken,
}

async fn oauth_authorize_impl(state: AppState, req: AuthorizeRequest) -> impl IntoResponse {
    if req.response_type.as_str() != "code" {
        return Err(Error::OAuth2(
            BasicErrorResponseType::InvalidRequest,
            "response_type must be code".into(),
        ));
    }

    // There is an early return when connection is not set
    let connection = req.connection.unwrap();

    let auth_client = get_auth_client(&connection, &state.env).await?;

    let requested_scopes = req
        .scope
        .map(|scope| {
            scope
                .split(' ')
                .map(|s| Scope::new(s.to_string()))
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default();

    let allowed_scopes = get_scopes(&state.db, &req.client_id)
        .await
        .ok_or(Error::OAuth2(
            BasicErrorResponseType::InvalidClient,
            "unable to find client".into(),
        ))?;

    if !requested_scopes.is_subset(&allowed_scopes) {
        return Err(Error::OAuth2(
            BasicErrorResponseType::InvalidScope,
            "requested scopes contain more than the allowed scopes".into(),
        ));
    }

    let ((auth_url, csrf_token, pkce_verifier), ty) = match auth_client {
        AuthClient::OAuth2(client) => (client.authorize_url(), AuthorizeFlowStateType::OAuth2),
        AuthClient::Oidc(client) => {
            let (auth_url, csrf_token, nonce, pkce_verifier) = client.authorize_url();

            (
                (auth_url, csrf_token, pkce_verifier),
                AuthorizeFlowStateType::Oidc { nonce },
            )
        }
    };

    state
        .kv
        .put(
            &format!("state:{}", csrf_token.secret()),
            AuthorizeFlowState {
                ty,
                connection,
                state: req.state,
                pkce_verifier,
                scopes: requested_scopes,
                client_id: req.client_id,
                redirect_uri: req.redirect_uri,
            },
        )
        .unwrap()
        .expiration_ttl(Duration::minutes(30).num_seconds() as u64)
        .execute()
        .await
        .map_err(Error::Kv)?;

    Ok(Redirect::temporary(auth_url.as_str()))
}

pub async fn oauth_authorize(
    State(state): State<AppState>,
    Query(req): Query<AuthorizeRequest>,
) -> Response {
    if req.connection.is_none() {
        return Html(include_str!(concat!(env!("OUT_DIR"), "/login.html"))).into_response();
    }

    let (tx, rx) = oneshot::channel();

    wasm_bindgen_futures::spawn_local(async move {
        let res = oauth_authorize_impl(state, req).await;
        tx.send(res).map_err(|_| ()).unwrap();
    });

    rx.await.unwrap().into_response()
}
