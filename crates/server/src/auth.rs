use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

/// Shared bearer token for all /v1/* routes. M2 uses one token for all
/// hosts; per-host tokens are M6.
#[derive(Clone)]
pub struct AuthToken(pub String);

/// Bearer-token gate. Rejects missing, empty, or wrong credentials.
pub async fn require_token(
    State(token): State<AuthToken>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let ok = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|tok| !tok.is_empty() && tok == token.0);
    if ok {
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
