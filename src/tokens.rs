use chrono::{Duration, Utc};
use oauth2::{AccessToken, AuthorizationCode, ClientId, RefreshToken};
use openidconnect::{
    core::{CoreIdToken, CoreIdTokenClaims, CoreJwsSigningAlgorithm},
    Audience, EmptyAdditionalClaims, EndUserEmail, EndUserFamilyName, EndUserGivenName,
    EndUserName, EndUserNickname, EndUserPhoneNumber, EndUserPictureUrl, EndUserUsername,
    IssuerUrl, StandardClaims, SubjectIdentifier,
};

use crate::{error::Error, gen_string, keys::get_rsa_key, users::User, AppState};

pub async fn id_token(
    state: &AppState,
    client_id: &ClientId,
    code: &AuthorizationCode,
    user: User,
    access_token: &AccessToken,
) -> Result<CoreIdToken, Error> {
    let signing_key = get_rsa_key(state).await?.ok_or(Error::MissingKeys)?;

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
            vec![Audience::new(client_id.to_string())],
            Utc::now() + Duration::seconds(36000),
            Utc::now(),
            claims,
            EmptyAdditionalClaims {},
        ),
        &signing_key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        Some(access_token),
        Some(code),
    )
    .map_err(Error::Jwt)?;

    Ok(id_token)
}

pub struct AccessRefreshTokenSet {
    pub access_token: AccessToken,
    pub expires_in: Duration,
    pub refresh_token: RefreshToken,
    pub refresh_expires_in: Duration,
}

pub fn generate_access_refresh_token_set() -> AccessRefreshTokenSet {
    let access_token = AccessToken::new(gen_string(32));
    let expires_in = Duration::weeks(1);

    let refresh_token = RefreshToken::new(gen_string(64));
    let refresh_expires_in = Duration::weeks(4);

    AccessRefreshTokenSet {
        access_token,
        expires_in,
        refresh_token,
        refresh_expires_in,
    }
}
