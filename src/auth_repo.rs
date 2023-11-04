use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use anyhow::{anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::{Error, Result},
    serde_format::{datetime_format, UtcDatetime},
};

#[derive(Clone)]
pub struct AuthRepo {
    users: Arc<RwLock<HashMap<String, StoredUser>>>,
    access_tokens: Arc<RwLock<HashMap<String, AccessToken>>>,
    refresh_tokens: Arc<RwLock<HashMap<String, RefreshToken>>>,
}

impl AuthRepo {
    pub fn new() -> Self {
        AuthRepo {
            users: Arc::new(RwLock::new(HashMap::new())),
            access_tokens: Arc::new(RwLock::new(HashMap::new())),
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

    pub fn insert_access_token(&self, access_token: AccessToken) -> Result<()> {
        if let Some(_) = self.access_tokens.read().unwrap().get(&access_token.value) {
            return Err(Error::DuplicateToken);
        }

        self.access_tokens
            .write()
            .unwrap()
            .insert(access_token.value.clone(), access_token);

        Ok(())
    }

    pub fn find_access_token(&self, access_token_value: &str) -> Result<Option<AccessToken>> {
        Ok(self
            .access_tokens
            .read()
            .unwrap()
            .get(access_token_value)
            .cloned())
    }

    pub fn insert_refresh_token(&self, refresh_token: RefreshToken) -> Result<()> {
        if let Some(_) = self
            .refresh_tokens
            .read()
            .unwrap()
            .get(&refresh_token.value)
        {
            return Err(Error::DuplicateToken);
        }

        self.refresh_tokens
            .write()
            .unwrap()
            .insert(refresh_token.value.clone(), refresh_token);

        Ok(())
    }

    pub fn find_refresh_token_by_value_and_ip(
        &self,
        refresh_token_value: &str,
        ip_address: &str,
    ) -> Result<Option<RefreshToken>> {
        let token = self
            .refresh_tokens
            .read()
            .unwrap()
            .get(refresh_token_value)
            .and_then(|val| {
                if val.ip_address != ip_address {
                    None
                } else {
                    Some(val)
                }
            })
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
    pub value: String,
    pub user_id: Uuid,
    pub ip_address: String,
    #[serde(with = "datetime_format")]
    pub expires: DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub value: String,
    pub user_id: Uuid,
    #[serde(with = "datetime_format")]
    pub expires: DateTime<Utc>,
}
