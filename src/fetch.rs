use serde::{de::DeserializeOwned, Serialize};

use crate::error::{Error, Result};

pub struct RequestBuilder<'a> {
    method: worker::Method,
    url: &'a str,
    headers: worker::Headers,
}

impl<'a> RequestBuilder<'a> {
    pub fn new(method: worker::Method, url: &'a str) -> Self {
        Self {
            method,
            url,
            headers: worker::Headers::new(),
        }
    }

    pub fn get(url: &'a str) -> Self {
        Self::new(worker::Method::Get, url)
    }

    pub fn set_header(mut self, name: &str, value: &str) -> Result<Self> {
        self.headers
            .set(name, value)
            .map_err(|_| Error::InvalidHeader)?;

        Ok(self)
    }

    pub fn set_headers(mut self, headers: worker::Headers) -> Self {
        self.headers = headers;
        self
    }

    pub async fn json<B: Serialize>(self, value: &B) -> Result<Response> {
        let body = serde_json::to_string(value).map_err(Error::Serde)?;

        self.body(&body).await
    }

    pub async fn body(self, value: &str) -> Result<Response> {
        self.make_req(Some(value)).await
    }

    pub async fn send(self) -> Result<Response> {
        self.make_req(None).await
    }

    async fn make_req(self, body: Option<&str>) -> Result<Response> {
        let req = worker::Request::new_with_init(
            self.url,
            worker::RequestInit::new()
                .with_method(self.method)
                .with_headers(self.headers)
                .with_body(body.map(worker::wasm_bindgen::JsValue::from_str)),
        )
        .map_err(Error::Worker)?;

        Ok(Response {
            inner: worker::Fetch::Request(req)
                .send()
                .await
                .map_err(Error::Worker)?,
        })
    }
}

pub struct Response {
    inner: worker::Response,
}

impl Response {
    pub fn status_code(&self) -> u16 {
        self.inner.status_code()
    }

    pub fn headers(&self) -> &worker::Headers {
        self.inner.headers()
    }

    pub async fn bytes(&mut self) -> Result<Vec<u8>> {
        self.inner.bytes().await.map_err(Error::Worker)
    }

    pub async fn text(&mut self) -> Result<String> {
        self.inner.text().await.map_err(Error::Worker)
    }

    pub async fn json<B: DeserializeOwned>(&mut self) -> Result<B> {
        self.inner.json().await.map_err(|err| match err {
            worker::Error::SerdeJsonError(e) => Error::Serde(e),
            e => Error::Worker(e),
        })
    }
}
