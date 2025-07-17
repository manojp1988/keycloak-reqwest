
use std::sync::Arc;
use std::sync::Mutex;
use async_trait::async_trait;
use http::Extensions;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next, Result as MiddlewareResult};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};

pub struct TokenMiddleware {
    client_id: String,
    client_secret: String,
    token_url: String,
    token_cache: Arc<Mutex<Option<String>>>,
}

impl TokenMiddleware {
    pub fn new(client_id: String, client_secret: String, token_url: String) -> Self {
        Self {
            client_id,
            client_secret,
            token_url,
            token_cache: Arc::new(Mutex::new(None)),
        }
    }

    async fn fetch_token(&self) -> Option<String> {
        let client_id = &self.client_id;
        let client_secret = &self.client_secret;
        let token_url = &self.token_url;
        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
        ];
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .ok()?;
        let resp = client
            .post(token_url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await
            .ok()?;
        if resp.status().is_success() {
            let json: serde_json::Value = resp.json().await.ok()?;
            json.get("access_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        } else {
            None
        }
    }
}

#[async_trait]
impl Middleware for TokenMiddleware {
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> MiddlewareResult<Response> {
        // Check if token is cached (do not hold lock across await)
        let token_opt = {
            let token_guard = self.token_cache.lock().unwrap();
            token_guard.clone()
        };
        let token = if let Some(token) = token_opt {
            tracing::info!("Token returning from cache");
            token
        } else {
            let token = self.fetch_token().await;
            let mut token_guard = self.token_cache.lock().unwrap();
            *token_guard = token.clone();

            tracing::info!("Fetching new token from keycloak");

            token.unwrap_or_default()
        };
        if !token.is_empty() {
            req.headers_mut().insert(
                AUTHORIZATION,
                format!("Bearer {}", token).parse().unwrap(),
            );
            tracing::info!("Token set in request headers");
        }
        next.run(req, extensions).await
    }
}
