# auth.worker

⚠️ WIP ⚠️ Authentication service built on [Cloudflare Workers](https://workers.cloudflare.com/) with Rust.

## Getting started

```sh
# build project
$ npm run build

# start dev server
$ npm run dev

# deploy to Cloudflare
$ npm run deploy
```

## User

Users are normalized to make working with different providers easier.

## Providers

Providers are defined in `src/providers` and configured using TOML. `client-id`, `client-secret`, and `callback` are provided through [Worker environment variables](https://developers.cloudflare.com/workers/platform/environment-variables/).

```toml
name = "discord"

[style]
display-name = "Discord"
icon-url = "https://example.com/icons/discord.png"
background-color = "#5865f2"
background-color-hover = "#707bf4"

[env]
client-id = "DISCORD_CLIENT_ID"
client-secret = "DISCORD_CLIENT_SECRET"
scopes = ["identify", "email"]

[url]
auth = "https://discord.com/api/oauth2/authorize"
token = "https://discord.com/api/oauth2/token"
callback = "DISCORD_CALLBACK_URL"
```

After acquiring the access token a function to fetch the user profile is called. Providers can make requests to any API required and return the normalized user object.

```rs
pub async fn fetch_user(access_token: &str) -> Result<User>;
```
