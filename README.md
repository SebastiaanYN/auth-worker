# auth worker

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

## Config

`config.toml` should contain the domain the Worker is under and a list of providers and their scopes.

```toml
domain = "https://auth.cf.sebastiaanyn.me"

[providers]
discord = ["identify", "email"]
github = ["user:email"]
```

## Providers

Providers are defined in `src/providers` and configured using TOML. Client ID and secret are provided through [Worker environment variables](https://developers.cloudflare.com/workers/platform/environment-variables/) prefixed with the provider name, such as `DISCORD_CLIENT_ID` and `DISCORD_CLIENT_SECRET`.

```toml
name = "discord"

[style]
display-name = "Discord"
background-color = "#5865f2"
background-color-hover = "#707bf4"

[url]
auth = "https://discord.com/api/oauth2/authorize"
token = "https://discord.com/api/oauth2/token"
```

After acquiring the access token a function to fetch the user profile is called. Providers can make requests to any API required and return the normalized user object.

```rs
pub async fn fetch_user(access_token: &str) -> Result<User>;
```
