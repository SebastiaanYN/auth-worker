use std::collections::HashSet;

use oauth2::{AccessToken, ClientId, CsrfToken, RefreshToken, Scope};
use openidconnect::core::CoreTokenResponse;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuthorizeFlowState {
    pub connection: String,
    pub state: CsrfToken,
    pub scopes: HashSet<Scope>,
    pub client_id: ClientId,
    pub redirect_uri: String,
}

#[derive(Serialize, Deserialize)]
pub struct CodeFlowState {
    pub reply: CoreTokenResponse,
    pub client_id: ClientId,
    pub redirect_uri: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenMetadata {
    pub client_id: String,
    pub scopes: HashSet<Scope>,
}

#[derive(Serialize, Deserialize)]
pub struct ConnectionTokens {
    pub access_token: AccessToken,
    pub refresh_token: Option<RefreshToken>,
    pub expires_in: std::time::Duration,
}
