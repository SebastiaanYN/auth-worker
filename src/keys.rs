use crate::{error::Error, gen_string, AppState};
use chrono::{DateTime, Utc};
use openidconnect::{
    core::{CoreJsonWebKeySet, CoreRsaPrivateSigningKey},
    JsonWebKey, JsonWebKeyId, PrivateSigningKey,
};
use rsa::{pkcs1::EncodeRsaPrivateKey, pkcs8::DecodePrivateKey};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use worker::js_sys;

mod sys {
    use wasm_bindgen::prelude::wasm_bindgen;
    use worker::js_sys::Promise;

    #[wasm_bindgen(module = "/js/pem.js")]
    extern "C" {
        pub fn generate_pem() -> Promise;
    }
}

#[derive(Serialize, Deserialize)]
struct Pem {
    kid: JsonWebKeyId,
    created_at: DateTime<Utc>,
    pem: String,
}

async fn generate_pem() -> Pem {
    let pem: String = JsFuture::from(sys::generate_pem())
        .await
        .unwrap()
        .unchecked_into::<js_sys::JsString>()
        .into();

    // We need to go from PKCS#8 to PKCS#1 because openidconnect only allows parsing of PKCS#1
    // while JavaScript only allows for serializing to PKCS#8. Fun :)
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(&pem).unwrap();
    let pem = key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap();

    Pem {
        pem: pem.to_string(),
        kid: JsonWebKeyId::new(gen_string(16)),
        created_at: Utc::now(),
    }
}

async fn get_pem(state: &AppState, name: &str) -> Result<Option<Pem>, Error> {
    state.kv.get(name).json::<Pem>().await.map_err(Error::Kv)
}

async fn get_key(state: &AppState, name: &str) -> Result<Option<CoreRsaPrivateSigningKey>, Error> {
    let key = get_pem(state, name)
        .await?
        .and_then(|pem| CoreRsaPrivateSigningKey::from_pem(&pem.pem, Some(pem.kid)).ok());

    Ok(key)
}

pub async fn get_rsa_key(state: &AppState) -> Result<Option<CoreRsaPrivateSigningKey>, Error> {
    get_key(state, "rsa").await
}

pub async fn get_jwks(state: &AppState) -> Result<CoreJsonWebKeySet, Error> {
    let jwk = get_rsa_key(state)
        .await?
        .map(|key| key.as_verification_key());

    let jwk_old = get_key(state, "rsa:old")
        .await?
        .map(|key| key.as_verification_key());

    let keys = match (jwk, jwk_old) {
        (Some(a), Some(b)) if a.key_id() != b.key_id() => vec![a, b],
        (Some(a), _) => vec![a],
        (_, Some(b)) => vec![b],
        _ => vec![],
    };

    Ok(CoreJsonWebKeySet::new(keys))
}

async fn write_pem(state: &AppState, name: &str, pem: &Pem) -> Result<(), Error> {
    state
        .kv
        .put(name, pem)
        .unwrap()
        .execute()
        .await
        .map_err(Error::Kv)
}

pub async fn rotate_keys(state: &AppState) -> Result<(), Error> {
    let curr_pem = get_pem(state, "rsa").await?;

    let Some(curr_pem) = curr_pem else {
        let pem = generate_pem().await;
        write_pem(state, "rsa", &pem).await?;
        return Ok(());
    };

    // TODO: follow configurable token expiration time
    let elapsed = Utc::now() - curr_pem.created_at;
    if elapsed.num_hours() < 1 {
        return Ok(());
    }

    write_pem(state, "rsa:old", &curr_pem).await?;

    let new_pem = generate_pem().await;
    write_pem(state, "rsa", &new_pem).await?;

    Ok(())
}
