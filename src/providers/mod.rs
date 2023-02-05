use crate::{
    error::{Error, Result},
    user::User,
};

mod discord;
mod github;

pub struct Provider {
    pub auth_url: &'static str,
    pub token_url: &'static str,
    pub callback_url: &'static str,
    pub scopes: &'static [&'static str],
}

include!(concat!(env!("OUT_DIR"), "/providers.rs"));
