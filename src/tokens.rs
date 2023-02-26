use chrono::{Duration, Utc};
use oauth2::{AccessToken, RefreshToken};
use openidconnect::{
    core::{
        CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
        CoreRsaPrivateSigningKey,
    },
    Audience, EmptyAdditionalClaims, EndUserEmail, EndUserFamilyName, EndUserGivenName,
    EndUserName, EndUserNickname, EndUserPhoneNumber, EndUserPictureUrl, EndUserUsername,
    IssuerUrl, JsonWebTokenError, PrivateSigningKey, StandardClaims, SubjectIdentifier,
};

use crate::{gen_string, users::User, AppState};

fn rsa_priv_key(state: &AppState) -> CoreRsaPrivateSigningKey {
    let rsa_priv_pem = state
        .env
        .var("PRIV_KEY")
        .expect("RSA private key not set")
        .to_string();

    openidconnect::core::CoreRsaPrivateSigningKey::from_pem(&rsa_priv_pem, None)
        .expect("invalid RSA private key")
}

pub fn id_token(
    user: User,
    state: &AppState,
    access_token: &AccessToken,
) -> Result<CoreIdToken, JsonWebTokenError> {
    let claims = StandardClaims::new(SubjectIdentifier::new(user.id))
        .set_email(user.email.map(EndUserEmail::new))
        .set_email_verified(user.email_verified)
        .set_family_name(user.family_name.map(EndUserFamilyName::new).map(Into::into))
        .set_given_name(user.given_name.map(EndUserGivenName::new).map(Into::into))
        .set_preferred_username(user.username.map(EndUserUsername::new).map(Into::into))
        .set_name(user.name.map(EndUserName::new).map(Into::into))
        .set_nickname(user.nickname.map(EndUserNickname::new).map(Into::into))
        .set_picture(user.picture.map(EndUserPictureUrl::new).map(Into::into))
        .set_phone_number(
            user.phone_number
                .map(EndUserPhoneNumber::new)
                .map(Into::into),
        )
        .set_phone_number_verified(user.phone_verified);

    let id_token = CoreIdToken::new(
        CoreIdTokenClaims::new(
            IssuerUrl::new(env!("DOMAIN").to_string()).expect("invalid issuer URL"),
            vec![Audience::new(env!("CLIENT_ID").to_string())],
            Utc::now() + Duration::seconds(36000),
            Utc::now(),
            claims,
            EmptyAdditionalClaims {},
        ),
        &rsa_priv_key(state),
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        Some(access_token),
        None,
    )?;

    Ok(id_token)
}

pub fn create_jwks(state: &AppState) -> CoreJsonWebKeySet {
    openidconnect::core::CoreJsonWebKeySet::new(vec![rsa_priv_key(state).as_verification_key()])
}

pub struct AccessRefreshTokenSet {
    pub access_token: AccessToken,
    pub expires_in: chrono::Duration,
    pub refresh_token: RefreshToken,
    pub refresh_expires_in: chrono::Duration,
}

pub fn generate_access_refresh_token_set() -> AccessRefreshTokenSet {
    let access_token = AccessToken::new(gen_string(32));
    let expires_in = chrono::Duration::weeks(1);

    let refresh_token = RefreshToken::new(gen_string(64));
    let refresh_expires_in = chrono::Duration::weeks(4);

    AccessRefreshTokenSet {
        access_token,
        expires_in,
        refresh_token,
        refresh_expires_in,
    }
}
