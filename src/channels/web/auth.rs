//! Bearer token authentication middleware for the web gateway.

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use subtle::ConstantTimeEq;

/// Shared auth state injected via axum middleware state.
#[derive(Clone)]
pub struct AuthState {
    pub token: String,
}

impl AuthState {
    pub fn is_valid(&self, candidate: &str) -> bool {
        bool::from(candidate.as_bytes().ct_eq(self.token.as_bytes()))
    }
}

/// Auth middleware that validates bearer token from header or session cookie.
///
/// Query-parameter auth is intentionally rejected to avoid token leakage
/// through URLs, browser history, and logs.
pub async fn auth_middleware(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    // Try Authorization header first (constant-time comparison)
    if let Some(auth_header) = headers.get("authorization")
        && let Ok(value) = auth_header.to_str()
        && let Some(token) = value.strip_prefix("Bearer ")
        && auth.is_valid(token)
    {
        return next.run(request).await;
    }

    // Fall back to cookie for browser EventSource connections.
    if let Some(cookie_header) = headers.get("cookie")
        && let Ok(cookie_str) = cookie_header.to_str()
    {
        for pair in cookie_str.split(';') {
            let part = pair.trim();
            if let Some(token) = part.strip_prefix("ironclaw_session=")
                && auth.is_valid(token)
            {
                return next.run(request).await;
            }
        }
    }

    (StatusCode::UNAUTHORIZED, "Invalid or missing auth token").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_state_clone() {
        let state = AuthState {
            token: "test-token".to_string(),
        };
        let cloned = state.clone();
        assert_eq!(cloned.token, "test-token");
    }
}
