use serde::Deserialize;

use crate::{error::Result, fetch, user::User};

#[derive(Deserialize)]
struct Discord {
    id: String,
    username: String,
    avatar: Option<String>,
    verified: Option<bool>,
    email: Option<String>,
}

pub async fn fetch_user(access_token: &str) -> Result<User> {
    let discord = fetch::RequestBuilder::get("https://discord.com/api/users/@me")
        .set_header("Authorization", &format!("Bearer {access_token}"))?
        .send()
        .await?
        .json::<Discord>()
        .await?;

    Ok(User {
        username: Some(discord.username),
        picture: discord.avatar.map(|avatar| {
            let ext = if avatar.starts_with("a_") {
                "gif"
            } else {
                "png"
            };

            let user_id = &discord.id;
            format!("https://cdn.discordapp.com/avatars/{user_id}/{avatar}.{ext}")
        }),
        email: discord.email,
        email_verified: discord.verified,
        ..User::default_with_user_id(discord.id)
    })
}
