use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use anyhow::{anyhow, bail};
use uuid::Uuid;

use crate::{
    error::{Error, Result},
    user::StoredUser,
};

#[derive(Clone)]
pub struct UserRepo {
    users: Arc<RwLock<HashMap<String, StoredUser>>>,
    refresh_tokens: Arc<RwLock<HashMap<String, String>>>,
}

impl UserRepo {
    pub fn new() -> Self {
        UserRepo {
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

    pub fn insert_user(&mut self, user: StoredUser) -> Result<StoredUser> {
        if let Ok(_) = self.get_user_by_email(&user.email) {
            return Err(anyhow!("The specified user already exists").into());
        }

        self.users
            .write()
            .unwrap()
            .insert(user.uuid.to_string().clone(), user.clone());

        Ok(user)
    }

    pub fn insert_refresh_token(&mut self, user_uuid: &Uuid, refresh_token: String) -> Result<()> {
        self.refresh_tokens
            .write()
            .unwrap()
            .insert(user_uuid.to_string(), refresh_token);

        Ok(())
    }

    // https://stackoverflow.com/questions/56133083/how-to-generate-a-refresh-token
    pub fn find_refresh_token_by_user_uuid(&self, user_uuid: Uuid) -> Result<Option<String>> {
        let token = self
            .refresh_tokens
            .read()
            .unwrap()
            .values()
            .find(|)
            .map(String::from);

        Ok(token)
    }
}