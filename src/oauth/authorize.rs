use std::{collections::HashSet, fmt::Debug};

use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::Duration;
use futures::channel::oneshot;
use oauth2::{basic::BasicErrorResponseType, ClientId, CsrfToken, ResponseType, Scope};
use serde::{Deserialize, Serialize};

use crate::{applications, error::Error, AppState};

use super::{get_oauth_client, states::AuthorizeFlowState};

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

    let oauth = get_oauth_client(&connection, &state.env)?;

    let requested_scopes = req
        .scope
        .map(|scope| {
            scope
                .split(' ')
                .map(|s| Scope::new(s.to_string()))
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default();

    let allowed_scopes = applications::get_scopes(&state.db, &req.client_id)
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

    let (auth_url, csrf_token) = oauth
        .client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".to_string()))
        .add_scopes(oauth.scopes)
        .url();

    state
        .kv
        .put(
            &format!("state:{}", csrf_token.secret()),
            AuthorizeFlowState {
                connection,
                state: req.state,
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
