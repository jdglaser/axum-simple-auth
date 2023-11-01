use anyhow::anyhow;
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Error;

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub uuid: Uuid,
    pub email: String,
    pub role: Role,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Error> {
        let authorized_user = parts
            .extensions
            .get::<AuthenticatedUser>()
            .ok_or(Error::Unauthorized)?
            .to_owned();

        Ok(authorized_user)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredUser {
    pub uuid: Uuid,
    pub email: String,
    pub role: Role,
    pub hashed_password: String,
    pub salt: String,
}

#[derive(PartialEq, PartialOrd, Serialize, Deserialize, Clone)]
pub enum Role {
    User = 1,
    Admin = 2,
}
