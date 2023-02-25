use chrono::{Duration, Utc};
use oauth2::AccessToken;
use openidconnect::{
    core::{
        CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
        CoreRsaPrivateSigningKey,
    },
    Audience, EmptyAdditionalClaims, EndUserEmail, EndUserFamilyName, EndUserGivenName,
    EndUserName, EndUserNickname, EndUserPhoneNumber, EndUserPictureUrl, EndUserUsername,
    IssuerUrl, JsonWebTokenError, PrivateSigningKey, StandardClaims, SubjectIdentifier,
};

use crate::user;

pub fn id_token(
    user: user::User,
    rsa_priv_pem: &str,
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
            IssuerUrl::new(std::env!("DOMAIN").to_string()).expect("invalid issuer URL"),
            vec![Audience::new(std::env!("CLIENT_ID").to_string())],
            Utc::now() + Duration::seconds(36000),
            Utc::now(),
            claims,
            EmptyAdditionalClaims {},
        ),
        &CoreRsaPrivateSigningKey::from_pem(rsa_priv_pem, None).expect("invalid RSA private key"),
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        Some(access_token),
        None,
    )?;

    Ok(id_token)
}

pub fn create_jwks(rsa_priv_pem: &str) -> CoreJsonWebKeySet {
    openidconnect::core::CoreJsonWebKeySet::new(vec![
        openidconnect::core::CoreRsaPrivateSigningKey::from_pem(rsa_priv_pem, None)
            .expect("invalid RSA private key")
            .as_verification_key(),
    ])
}
