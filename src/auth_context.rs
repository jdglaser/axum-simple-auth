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
    auth_repo::{AuthRepo, RefreshToken, Role, StoredUser},
    auth_router::{
        LoginRequest, LoginResponse, RefreshAccessTokenRequest, RefreshAccessTokenResponse,
        RegisterRequest,
    },
    error::{Error, Result},
    log::error,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub exp: i64,
}

#[derive(Clone)]
pub struct AuthContext {
    secret: String,
    auth_repo: AuthRepo,
}

impl AuthContext {
    pub fn new(user_repo: AuthRepo, secret: String) -> Self {
        Self {
            auth_repo: user_repo,
            secret,
        }
    }

    pub fn login(
        &self,
        LoginRequest { email, password }: LoginRequest,
        client_ip: String,
    ) -> Result<LoginResponse> {
        let user = self
            .auth_repo
            .get_user_by_email(&email)
            .map_err(|_| Error::Unauthorized)?;

        let hashed_login_password = Self::hash_password(&password, &user.salt)?;
        if hashed_login_password != user.hashed_password {
            error("Incorrect password");
            return Err(Error::Unauthorized);
        }

        let refresh_token = self.generate_refresh_token(&user.user_id, &client_ip)?;
        let access_token = self.generate_access_token(&user.user_id)?;

        Ok(LoginResponse {
            access_token,
            refresh_token: refresh_token.value,
        })
    }

    pub fn register_user(
        &self,
        RegisterRequest { email, password }: RegisterRequest,
    ) -> Result<()> {
        let salt = SaltString::generate(&mut OsRng);

        let uuid = Uuid::new_v4();

        let hashed_password = Self::hash_password(&password, salt.as_str())?;
        let user = StoredUser {
            user_id: uuid,
            email,
            hashed_password,
            role: Role::User,
            salt: salt.to_string(),
        };
        self.auth_repo.insert_user(user)?;

        Ok(())
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
        self.auth_repo.get_user(&uuid)
    }

    pub fn refresh_access_token(
        &self,
        RefreshAccessTokenRequest { refresh_token }: &RefreshAccessTokenRequest,
        client_ip_address: &str,
    ) -> Result<RefreshAccessTokenResponse> {
        let stored_refresh_token = self
            .auth_repo
            .find_refresh_token_by_value_and_ip(refresh_token, &client_ip_address)?
            .ok_or(Error::Unauthorized)?;

        let token_expired_at_utc = Utc
            .timestamp_opt(stored_refresh_token.expires, 0)
            .single()
            .ok_or(anyhow!(
                "Problem converting epoch timestamp to DateTime type."
            ))?;

        if refresh_token != &stored_refresh_token.value || Utc::now() > token_expired_at_utc {
            return Err(Error::Unauthorized);
        }

        let new_refresh_token =
            self.generate_refresh_token(&stored_refresh_token.user_id, &client_ip_address)?;
        let new_access_token = self.generate_access_token(&stored_refresh_token.user_id)?;

        Ok(RefreshAccessTokenResponse {
            access_token: new_access_token,
            refresh_token: new_refresh_token.value,
        })
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

    fn generate_access_token(&self, user_id: &Uuid) -> Result<String> {
        let expiration = Utc::now()
            .checked_add_signed(chrono::Duration::seconds(30))
            .expect("valid timestamp")
            .timestamp();

        Ok(self
            .sign_token(TokenClaims {
                sub: user_id.to_string(),
                exp: expiration,
            })
            .map_err(|_| anyhow!("Failed to sign access token"))?)
    }

    fn generate_refresh_token(
        &self,
        user_id: &Uuid,
        client_ip_address: &str,
    ) -> Result<RefreshToken> {
        let refresh_token_string: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let refresh_token_expiration = Utc::now()
            .checked_add_signed(chrono::Duration::days(7))
            .ok_or(anyhow!(
                "Unable to add duration to refresh token expiration"
            ))?
            .timestamp();

        let refresh_token_id = Uuid::new_v4();

        let mut refresh_token = RefreshToken {
            uuid: refresh_token_id,
            value: refresh_token_string,
            user_id: user_id.clone(),
            ip_address: client_ip_address.to_owned(),
            expires: refresh_token_expiration,
        };

        while let Err(Error::DuplicateRefreshToken) =
            self.auth_repo.insert_refresh_token(refresh_token.clone())
        {
            let refresh_token_string: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(30)
                .map(char::from)
                .collect();

            refresh_token = RefreshToken {
                uuid: refresh_token_id,
                value: refresh_token_string,
                user_id: user_id.clone(),
                ip_address: client_ip_address.to_owned(),
                expires: refresh_token_expiration,
            };
        }

        Ok(refresh_token)
    }
}

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
            .take(32)
            .map(char::from)
            .collect();
        println!("{:?}", rand_str);
        Ok(())
    }
}
