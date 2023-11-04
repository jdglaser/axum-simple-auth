use std::net::SocketAddr;

use axum::{
    extract::ConnectInfo,
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
pub struct RefreshAccessTokenRequest {
    pub refresh_token: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshAccessTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

pub fn auth_router() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/login", post(login_handler))
        .route("/register", post(register_handler))
        .route("/refresh", post(refresh_token_handler))
}

async fn login_handler(
    auth_ctx: AuthContext,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(login_request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    Ok(Json(auth_ctx.login(login_request, addr.to_string())?))
}

async fn register_handler(
    auth_ctx: AuthContext,
    Json(register_request): Json<RegisterRequest>,
) -> Result<axum::http::StatusCode> {
    auth_ctx.register_user(register_request)?;

    Ok(StatusCode::OK)
}

async fn refresh_token_handler(
    auth_ctx: AuthContext,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(refresh_access_token_request): Json<RefreshAccessTokenRequest>,
) -> Result<Json<RefreshAccessTokenResponse>> {
    Ok(Json(auth_ctx.refresh_access_token(
        &refresh_access_token_request,
        &addr.to_string(),
    )?))
}
