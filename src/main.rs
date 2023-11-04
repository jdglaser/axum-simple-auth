use std::{collections::HashMap, net::SocketAddr};

use anyhow::{Context, Result};
use auth_context::AuthenticatedUser;
use auth_router::auth_router;
use auth_service::AuthLayer;
use axum::{
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use require_auth_service::RequireAuthLayer;
use serde_json::{json, Value};
use tower_http::services::ServeDir;

mod auth_context;
mod auth_repo;
mod auth_router;
mod auth_service;
mod error;
mod log;
mod require_auth_service;
mod serde_format;

#[tokio::main]
async fn main() -> Result<()> {
    log::info("Starting service!");

    let user_repo = auth_repo::AuthRepo::new();

    let app_state = AppState {
        user_repo: user_repo.clone(),
    };

    let api_router = Router::new()
        .route("/hello", get(|| async { Json(json!({"Hello": "World!"})) }))
        .route("/test-auth", get(test_auth_handler))
        .layer(RequireAuthLayer {})
        .merge(auth_router());

    let app = Router::new()
        .nest("/api", api_router)
        .nest_service("/", ServeDir::new("./static"))
        .layer(AuthLayer::new(user_repo, "12345".to_string()))
        .with_state(app_state);

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("failed to start server")?;

    Ok(())
}

async fn test_auth_handler(user: AuthenticatedUser) -> Json<AuthenticatedUser> {
    Json(user)
}

#[derive(Clone)]
pub struct AppState {
    pub user_repo: auth_repo::AuthRepo,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use anyhow::Result;
    use serde_json::Value;

    use crate::auth_router::LoginRequest;

    #[tokio::test]
    async fn login() -> Result<()> {
        let request = LoginRequest {
            email: "jarred.glaser@gmail.com".to_string(),
            password: "123456".to_string(),
        };

        let res = reqwest::Client::new()
            .post("http://localhost:3000/api/login")
            .json(&request)
            .send()
            .await?;

        //println!("{:?}", res.text().await?);
        println!("{:?}", res.json::<HashMap<String, Value>>().await?);

        Ok(())
    }
}
