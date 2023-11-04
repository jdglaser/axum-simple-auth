use anyhow::anyhow;
use axum::{body::Body, http::header::AUTHORIZATION, http::Request, response::Response};
use futures_util::future::BoxFuture;
use reqwest::StatusCode;
use std::task::{Context, Poll};
use tower::{Layer, Service};

use crate::{
    auth_context::{AuthContext, AuthenticatedUser},
    error::Result,
    log::{self, error},
};

#[derive(Clone)]
pub struct RequireAuthLayer;

impl<S> Layer<S> for RequireAuthLayer {
    type Service = RequireAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireAuthService { inner }
    }
}

#[derive(Clone)]
pub struct RequireAuthService<S> {
    inner: S,
}

impl<S> RequireAuthService<S> {
    async fn authenticate_request(request: &mut Request<Body>) -> Result<()> {
        let access_token = request
            .headers()
            .get(AUTHORIZATION)
            .ok_or(anyhow!("Authorization header not found"))?
            .to_str()?
            .to_owned()
            .split("Bearer ")
            .collect::<Vec<&str>>()
            .get(1)
            .ok_or(anyhow!(
                "Failed to get access token from authorization header"
            ))?
            .to_owned()
            .to_owned();

        let auth_context = request
            .extensions_mut()
            .get_mut::<AuthContext>()
            .expect("Missing AuthContext. Is AuthLayer installed?");

        let claims = auth_context.verify_token(&access_token)?;

        let stored_user = auth_context.get_user(&claims.sub)?;

        let authenticated_user = AuthenticatedUser {
            uuid: stored_user.user_id,
            email: stored_user.email,
            role: stored_user.role,
        };

        request.extensions_mut().insert(authenticated_user);

        Ok(())
    }
}

impl<S> Service<Request<Body>> for RequireAuthService<S>
where
    S: Service<Request<Body>, Response = Response> + Send + 'static + Clone,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let auth_result = Self::authenticate_request(&mut request).await;
            if let Err(err) = auth_result {
                error(format!("Failed to authenticate user: {:?}", err));
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Default::default())
                    .unwrap());
            }
            let future = inner.call(request);
            let response: Response = future.await?;
            Ok(response)
        })
    }
}
