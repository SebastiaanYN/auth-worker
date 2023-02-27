use axum::{response::IntoResponse, routing::get, Json, Router};
use oauth2::{AuthUrl, Scope, TokenUrl};
use openidconnect::{
    core::{
        CoreClaimName, CoreGrantType, CoreJwsSigningAlgorithm, CoreProviderMetadata,
        CoreResponseType, CoreSubjectIdentifierType,
    },
    EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeySetUrl, ResponseTypes,
};
use worker::body::Body;

use crate::AppState;

async fn openid_configuration() -> impl IntoResponse {
    let domain = env!("DOMAIN");

    let metadata = CoreProviderMetadata::new(
        IssuerUrl::new(domain.to_string()).unwrap(),
        AuthUrl::new(format!("{domain}/oauth/authorize")).unwrap(),
        JsonWebKeySetUrl::new(format!("{domain}/jwks")).unwrap(),
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![CoreSubjectIdentifierType::Public],
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_grant_types_supported(Some(vec![CoreGrantType::AuthorizationCode]))
    .set_token_endpoint(Some(
        TokenUrl::new(format!("{domain}/oauth/token")).unwrap(),
    ))
    // .set_userinfo_endpoint(Some(
    //     UserInfoUrl::new(format!("{domain}/userinfo")).unwrap(),
    // ))
    .set_scopes_supported(Some(
        ["openid", "profile", "email", "read:user_idp_tokens"]
            .into_iter()
            .map(|s| Scope::new(s.into()))
            .collect(),
    ))
    .set_claims_supported(Some(
        [
            "iss",
            "aud",
            "exp",
            "iat",
            "at_hash",
            "c_hash",
            //
            "sub",
            "email",
            "email_verified",
            "family_name",
            "given_name",
            "preferred_username",
            "name",
            "nickname",
            "picture",
            "phone_number",
            "phone_number_verified",
        ]
        .into_iter()
        .map(|c| CoreClaimName::new(c.into()))
        .collect(),
    ));

    Json(metadata)
}

pub fn router() -> Router<AppState, Body> {
    Router::new().route("/openid-configuration", get(openid_configuration))
}
