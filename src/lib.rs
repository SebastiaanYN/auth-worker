use std::sync::Arc;

use axum::{
    extract::State,
    headers::{authorization::Bearer, Authorization},
    http::{HeaderMap, Request, Response},
    response::IntoResponse,
    routing::{get, post},
    Json, Router, TypedHeader,
};
use futures::channel::oneshot;
use oauth2::Scope;
use rand::{
    distributions::{Alphanumeric, DistString},
    thread_rng,
};
use reqwest::header;
use tower::Service;
use worker::{body::Body, event, kv::KvStore, Context, Env, ScheduleContext, ScheduledEvent};

mod applications;
mod auth;
mod d1;
mod error;
mod keys;
mod oauth;
mod oidc;
mod providers;
mod tokens;
mod users;
mod well_known;

use auth::states::TokenMetadata;
use error::Error;
use keys::{get_jwks, rotate_keys};

pub fn gen_string(len: usize) -> String {
    Alphanumeric.sample_string(&mut thread_rng(), len)
}

pub fn http_client() -> reqwest::Client {
    let mut headers = HeaderMap::new();
    headers.append(
        header::USER_AGENT,
        format!(
            "auth-worker v{} ({})",
            env!("CARGO_PKG_VERSION"),
            env!("DOMAIN"),
        )
        .parse()
        .unwrap(),
    );

    reqwest::ClientBuilder::new()
        .default_headers(headers)
        .build()
        .unwrap()
}

#[derive(Clone)]
pub struct AppState {
    env: Arc<Env>,
    db: Arc<d1::Database>,
    kv: Arc<KvStore>,
}

unsafe impl Send for AppState {}
unsafe impl Sync for AppState {}

impl AppState {
    fn new(env: Env) -> Self {
        let env = Arc::new(env);
        let db = Arc::new(d1::binding(&env, "DB").unwrap());
        let kv = Arc::new(env.kv("KV").unwrap());

        AppState { env, db, kv }
    }
}

async fn application(
    State(state): State<AppState>,
    Json(mut req): Json<applications::CreateApplication>,
) -> impl IntoResponse {
    let (tx, rx) = oneshot::channel();

    wasm_bindgen_futures::spawn_local(async move {
        let res = applications::create_application(&state.db, &mut req).await;
        tx.send(Json(res)).unwrap();
    });

    rx.await.unwrap()
}

async fn users_impl(state: AppState, authorization: Authorization<Bearer>) -> impl IntoResponse {
    let token = authorization.token();

    let token_meta = state
        .kv
        .get(&format!("token:access:{}", token))
        .json::<TokenMetadata>()
        .await
        .map_err(Error::Kv)?
        .ok_or(Error::InvalidAccessToken)?;

    if !token_meta
        .scopes
        .contains(&Scope::new("read:user_idp_tokens".to_string()))
    {
        return Err(Error::MissingPermission);
    }

    let tokens = state
        .kv
        .get(&format!("connection:{}:tokens", token_meta.client_id))
        .json()
        .await
        .map_err(Error::Kv)?
        .ok_or(Error::TokensNotFound)?;

    Ok(Json(tokens))
}

async fn users(
    State(state): State<AppState>,
    TypedHeader(req): TypedHeader<Authorization<Bearer>>,
) -> impl IntoResponse {
    let (tx, rx) = oneshot::channel();

    wasm_bindgen_futures::spawn_local(async move {
        let res = users_impl(state, req).await;
        tx.send(res).map_err(|_| ()).unwrap()
    });

    rx.await.unwrap()
}

async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    let (tx, rx) = oneshot::channel();

    wasm_bindgen_futures::spawn_local(async move {
        let jwks = get_jwks(&state).await;
        tx.send(jwks.map(Json)).unwrap();
    });

    rx.await.unwrap()
}

fn router() -> Router<AppState, Body> {
    Router::new()
        .route("/application", post(application))
        .route("/users", get(users))
        .route("/jwks", get(jwks))
        .nest("/oauth", auth::router())
        .nest("/.well-known", well_known::router())
}

#[event(fetch)]
async fn fetch(req: Request<Body>, env: Env, _ctx: Context) -> worker::Result<Response<Body>> {
    console_error_panic_hook::set_once();

    let res = router()
        .with_state(AppState::new(env))
        .call(req)
        .await
        .unwrap();

    Ok(res.map(Body::new))
}

#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let state = AppState::new(env);
    rotate_keys(&state).await.expect("failed to rotate keys");
}
