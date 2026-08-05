use axum::routing::get;
use axum::{Json, Router};

use crate::config::ServerConfig;
use crate::db;

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
        AppState::new(pool, ServerConfig::default()).await
    }
}

pub async fn build_app(state: AppState) -> Router {
    Router::new().route("/v1/ping", get(ping)).with_state(state)
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
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
