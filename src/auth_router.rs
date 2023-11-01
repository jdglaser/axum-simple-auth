use axum::{
    routing::{get, post},
    Json, Router,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::{auth_context::AuthContext, error::Result, AppState};

#[derive(Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

pub fn auth_router() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/login", post(login_handler))
        .route("/register", post(register_handler))
}

async fn login_handler(
    mut auth_ctx: AuthContext,
    Json(login_request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    Ok(Json(auth_ctx.login(login_request)?))
}

async fn register_handler(
    mut auth_ctx: AuthContext,
    Json(register_request): Json<RegisterRequest>,
) -> Result<axum::http::StatusCode> {
    auth_ctx.register_user(register_request)?;

    Ok(StatusCode::OK)
}
