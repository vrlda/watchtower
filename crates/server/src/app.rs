use axum::middleware;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::auth::{require_token, AuthToken};
use crate::config::ServerConfig;
use crate::db;
use crate::ingest;

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::SqlitePool,
    pub cfg: ServerConfig,
}

impl AppState {
    pub async fn new(pool: sqlx::SqlitePool, cfg: ServerConfig) -> Self {
        db::init_schema(&pool).await.expect("schema init failed");
        AppState { pool, cfg }
    }

    #[cfg(test)]
    pub async fn for_tests() -> Self {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory db");
        AppState::new(
            pool,
            ServerConfig {
                auth_token: "test-token".into(),
                ..Default::default()
            },
        )
        .await
    }
}

pub async fn build_app(state: AppState) -> Router {
    let auth_token = AuthToken(state.cfg.auth_token.clone());
    Router::new()
        .route("/v1/ping", get(ping))
        .route("/v1/telemetry", post(ingest::ingest))
        .layer(middleware::from_fn_with_state(auth_token, require_token))
        .with_state(state)
}

async fn ping() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "service": "watchtower-server" }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn ping_returns_ok() {
        let app = build_app(AppState::for_tests().await).await;
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/ping")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
