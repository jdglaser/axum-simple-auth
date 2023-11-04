use anyhow::Result;
use axum::{body::Body, extract::ConnectInfo, http::Request, response::Response, RequestExt};
use futures_util::future::BoxFuture;
use std::{
    net::SocketAddr,
    task::{Context, Poll},
};
use tower::{Layer, Service};

use crate::{auth_context::AuthContext, auth_repo::AuthRepo};

#[derive(Clone)]
pub struct AuthLayer {
    user_store: AuthRepo,
    secret: String,
}

impl AuthLayer {
    pub fn new(user_store: AuthRepo, secret: String) -> Self {
        AuthLayer { user_store, secret }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            user_store: self.user_store.clone(),
            secret: self.secret.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthService<S> {
    user_store: AuthRepo,
    secret: String,
    inner: S,
}

impl<S> Service<Request<Body>> for AuthService<S>
where
    S: Service<Request<Body>, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    // `BoxFuture` is a type alias for `Pin<Box<dyn Future + Send + 'a>>`
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        request.extensions_mut().insert(AuthContext::new(
            self.user_store.clone(),
            self.secret.clone(),
        ));

        let future = self.inner.call(request);
        Box::pin(async move {
            let response: Response = future.await?;
            Ok(response)
        })
    }
}
