use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use anyhow::{anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};

#[derive(Clone)]
pub struct AuthRepo {
    users: Arc<RwLock<HashMap<String, StoredUser>>>,
    refresh_tokens: Arc<RwLock<HashMap<String, RefreshToken>>>,
}

impl AuthRepo {
    pub fn new() -> Self {
        AuthRepo {
            users: Arc::new(RwLock::new(HashMap::new())),
            refresh_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn get_user(&self, user_id: &Uuid) -> Result<StoredUser> {
        let user = self
            .users
            .read()
            .unwrap()
            .get(&user_id.to_string())
            .ok_or(anyhow!("The specified user does not exist"))?
            .clone();

        Ok(user)
    }

    pub fn get_user_by_email(&self, user_email: &str) -> Result<StoredUser> {
        let binding = self.users.read().unwrap();
        let user = binding
            .values()
            .find(|&stored_user| stored_user.email == user_email)
            .ok_or(Error::NotFound)?;

        Ok(user.clone())
    }

    pub fn insert_user(&self, user: StoredUser) -> Result<StoredUser> {
        if let Ok(_) = self.get_user_by_email(&user.email) {
            return Err(anyhow!("The specified user already exists").into());
        }

        self.users
            .write()
            .unwrap()
            .insert(user.user_id.to_string().clone(), user.clone());

        Ok(user)
    }

    pub fn insert_refresh_token(&self, refresh_token: RefreshToken) -> Result<()> {
        if let Some(_) = self
            .refresh_tokens
            .read()
            .unwrap()
            .values()
            .find(|token| token.value == refresh_token.value)
        {
            return Err(Error::DuplicateRefreshToken);
        }

        self.refresh_tokens
            .write()
            .unwrap()
            .insert(refresh_token.uuid.to_string(), refresh_token);

        Ok(())
    }

    // https://stackoverflow.com/questions/56133083/how-to-generate-a-refresh-token
    pub fn find_refresh_token_by_value_and_ip(
        &self,
        refresh_token_value: &str,
        ip_address: &str,
    ) -> Result<Option<RefreshToken>> {
        let token = self
            .refresh_tokens
            .read()
            .unwrap()
            .values()
            .find(|token| token.value == refresh_token_value && token.ip_address == ip_address)
            .cloned();

        Ok(token)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredUser {
    pub user_id: Uuid,
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

#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub uuid: Uuid,
    pub value: String,
    pub user_id: Uuid,
    pub ip_address: String,
    pub expires: i64,
}
