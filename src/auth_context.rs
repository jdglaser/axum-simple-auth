use std::{collections::BTreeMap, str::FromStr};

use anyhow::{anyhow, bail};
use argon2::Argon2;
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use password_hash::{PasswordHasher, Salt, SaltString};
use rand::{distributions::Alphanumeric, Rng};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    auth_router::{LoginRequest, LoginResponse, RegisterRequest},
    error::{Error, Result},
    log::error,
    user::{AuthenticatedUser, Role, StoredUser},
    user_repo::UserRepo,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub exp: i64,
}

#[derive(Clone)]
pub struct AuthContext {
    secret: String,
    user_repo: UserRepo,
}

impl AuthContext {
    pub fn new(user_repo: UserRepo, secret: String) -> Self {
        Self { user_repo, secret }
    }

    pub fn login(
        &mut self,
        LoginRequest { email, password }: LoginRequest,
    ) -> Result<LoginResponse> {
        let user = self
            .user_repo
            .get_user_by_email(&email)
            .map_err(|_| Error::Unauthorized)?;

        let hashed_login_password = Self::hash_password(&password, &user.salt)?;
        if hashed_login_password != user.hashed_password {
            error("Incorrect password");
            return Err(Error::Unauthorized);
        }

        let refresh_token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();
        self.user_repo
            .insert_refresh_token(&user.uuid, refresh_token.clone())?;

        let expiration = Utc::now()
            .checked_add_signed(chrono::Duration::minutes(1))
            .expect("valid timestamp")
            .timestamp();

        Ok(LoginResponse {
            access_token: self.sign_token(TokenClaims {
                sub: user.uuid.to_string(),
                exp: expiration,
            })?,
            refresh_token,
        })
    }

    pub fn register_user(
        &mut self,
        RegisterRequest { email, password }: RegisterRequest,
    ) -> Result<()> {
        let salt = SaltString::generate(&mut OsRng);

        let uuid = Uuid::new_v4();

        let hashed_password = Self::hash_password(&password, salt.as_str())?;
        let user = StoredUser {
            uuid,
            email,
            hashed_password,
            role: Role::User,
            salt: salt.to_string(),
        };
        self.user_repo.insert_user(user)?;

        Ok(())
    }

    fn hash_password(password: &str, salt: &str) -> Result<String> {
        let argon2 = Argon2::default();
        let salt_string = SaltString::from_b64(salt).map_err(|err| {
            anyhow!(format!(
                "Problem decoding salt string: {:?}",
                err.to_string()
            ))
        })?;
        let hashed_password = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|err| anyhow!(format!("Problem hashing password: {:?}", err.to_string())))?
            .to_string();

        Ok(hashed_password)
    }

    fn sign_token(&self, claims: TokenClaims) -> Result<String> {
        let key: Hmac<Sha256> = Hmac::new_from_slice(self.secret.as_bytes())?;
        let token_str = claims.sign_with_key(&key)?;
        Ok(token_str)
    }

    pub fn verify_token(&self, token_str: &str) -> Result<TokenClaims> {
        let key: Hmac<Sha256> = Hmac::new_from_slice(self.secret.as_bytes())?;
        let claims: TokenClaims = token_str.verify_with_key(&key)?;

        let token_exp = Utc.timestamp_opt(claims.exp, 0).single().ok_or(anyhow!(
            "Problem converting epoch timestamp to DateTime type."
        ))?;

        if Utc::now() >= token_exp {
            return Err(Error::Anyhow(anyhow!("Token expired")));
        };
        Ok(claims)
    }

    pub fn get_user(&self, user_id: &str) -> Result<StoredUser> {
        let uuid = Uuid::from_str(user_id)?;
        self.user_repo.get_user(&uuid)
    }

    pub fn refresh_token(&self, refresh_token: &str) -> Result<TokenClaims> {}
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthContext
where
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Error> {
        let auth_ctx = parts
            .extensions
            .get::<AuthContext>()
            .ok_or(anyhow!("AuthContext layer not found"))?
            .to_owned();

        Ok(auth_ctx)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use anyhow::Result;
    use password_hash::SaltString;
    use rand::distributions::Alphanumeric;
    use rand::prelude::*;
    use rand_core::OsRng;

    #[test]
    fn test_string() -> Result<()> {
        let rand_str: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();
        println!("{:?}", rand_str);
        Ok(())
    }
}
