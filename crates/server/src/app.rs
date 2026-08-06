use axum::middleware;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::api_incidents;
use crate::auth::{require_token, AuthToken};
use crate::config::ServerConfig;
use crate::correlation::{merged_rules, Rule};
use crate::db;
use crate::events;
use crate::hosts;
use crate::ingest;
use crate::probes::Checker;
use tower_http::services::ServeDir;

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::SqlitePool,
    pub cfg: ServerConfig,
    pub checker: Checker,
    /// Effective correlation rules (config merged over built-in defaults).
    pub rules: Vec<Rule>,
    /// Max request body bytes accepted by ingest. Must fit the agent's
    /// maximum spool file (10 MB) plus envelope — a smaller cap would make
    /// the drain POST 400 and the agent would drop the whole file as
    /// "permanent".
    pub max_body_bytes: usize,
}

impl AppState {
    pub async fn new(pool: sqlx::SqlitePool, cfg: ServerConfig) -> Self {
        db::init_schema(&pool).await.expect("schema init failed");
        let rules = merged_rules(&cfg.rules);
        let checker = Checker::new();
        AppState {
            pool,
            cfg,
            checker,
            rules,
            max_body_bytes: crate::ingest::MAX_BODY_BYTES,
        }
    }

    #[cfg(test)]
    pub async fn for_tests() -> Self {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory db");
        let mut state = AppState::new(
            pool,
            ServerConfig {
                auth_token: "test-token".into(),
                ..Default::default()
            },
        )
        .await;
        state.max_body_bytes = 4096;
        state
    }
}

pub async fn build_app(state: AppState) -> Router {
    let auth_token = AuthToken(state.cfg.auth_token.clone());
    Router::new()
        .route("/v1/ping", get(ping))
        .route("/v1/telemetry", post(ingest::ingest))
        .route("/v1/heartbeat", post(hosts::heartbeat))
        .route("/v1/hosts", get(hosts::list_hosts))
        .route("/v1/events", get(events::list_events))
        .route("/v1/incidents", get(api_incidents::list_incidents))
        .route("/v1/incidents/{id}", get(api_incidents::get_incident))
        .route(
            "/v1/incidents/{id}/{action}",
            post(api_incidents::set_status_route),
        )
        .layer(middleware::from_fn_with_state(auth_token, require_token))
        .fallback_service(ServeDir::new(crate::ui_dir()))
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
    async fn ui_serves_index_html() {
        let app = build_app(AppState::for_tests().await).await;
        let resp = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("Watchtower"));
    }

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
