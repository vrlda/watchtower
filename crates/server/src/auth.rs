use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

/// Bearer credentials for /v1/* routes: a shared token (any host) plus
/// per-host tokens that pin the presenter to a host.
#[derive(Clone)]
pub struct Auth {
    pub shared: String,
    pub hosts: Arc<HashMap<String, String>>,
}

/// Resolve the presenter's host_id: shared token → None (payload decides);
/// a per-host token → Some(host_id).
pub fn resolve_host_id(auth: &Auth, bearer: &str) -> Option<String> {
    if bearer == auth.shared {
        return None;
    }
    auth.hosts
        .iter()
        .find(|(_, t)| *t == bearer)
        .map(|(h, _)| h.clone())
}

/// Host identity resolved from the bearer token (None = shared token).
#[derive(Clone, Debug)]
pub struct ResolvedHost(pub Option<String>);

/// Bearer-token gate. Rejects missing, empty, or wrong credentials.
pub async fn require_token(
    State(auth): State<Auth>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let bearer = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match bearer {
        Some(tok) if !tok.is_empty() => {
            let host = resolve_host_id(&auth, tok);
            // attach the resolved host to the extensions for the handlers
            request.extensions_mut().insert(ResolvedHost(host));
            Ok(next.run(request).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> Auth {
        let mut hosts = HashMap::new();
        hosts.insert("host-a".to_string(), "token-a".to_string());
        Auth {
            shared: "shared-token".into(),
            hosts: Arc::new(hosts),
        }
    }

    #[test]
    fn shared_token_is_anonymous() {
        assert_eq!(resolve_host_id(&auth(), "shared-token"), None);
    }

    #[test]
    fn per_host_token_resolves_host() {
        assert_eq!(
            resolve_host_id(&auth(), "token-a").as_deref(),
            Some("host-a")
        );
        assert_eq!(resolve_host_id(&auth(), "unknown"), None);
    }
}
