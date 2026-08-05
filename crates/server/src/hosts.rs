use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use wt_common::Heartbeat;

use crate::app::AppState;

/// POST /v1/heartbeat — upsert host, keep last-seen + version. The watchdog
/// (missing heartbeat → incident) is M4.
pub async fn heartbeat(State(state): State<AppState>, Json(hb): Json<Heartbeat>) -> Response {
    match upsert_host(&state.pool, &hb).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => {
            eprintln!("heartbeat store failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "store failed" })),
            )
                .into_response()
        }
    }
}

pub async fn upsert_host(pool: &sqlx::SqlitePool, hb: &Heartbeat) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO hosts (host_id, first_seen, last_seen, version)
         VALUES (?1, ?2, ?2, ?3)
         ON CONFLICT(host_id) DO UPDATE SET last_seen = ?2, version = ?3",
    )
    .bind(&hb.host_id)
    .bind(hb.ts)
    .bind(&hb.version)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Deserialize)]
pub struct HostQuery {
    #[serde(default)]
    host: Option<String>,
}

/// GET /v1/hosts — host registry.
pub async fn list_hosts(
    State(state): State<AppState>,
    Query(q): Query<HostQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let hosts = fetch_hosts(&state.pool, q.host.as_deref())
        .await
        .map_err(|e| {
            eprintln!("hosts list failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(Json(json!({ "hosts": hosts })))
}

/// NOTE: queue_len is not persisted in M2 (schema has no column); it is
/// reported as 0. The M4 watchdog needs queue-growth detection and must add
/// the column then.
pub async fn fetch_hosts(
    pool: &sqlx::SqlitePool,
    host: Option<&str>,
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (String, i64, i64, String)>(
        "SELECT host_id, first_seen, last_seen, version
         FROM hosts
         WHERE (?1 IS NULL OR host_id = ?1)
         ORDER BY host_id",
    )
    .bind(host)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(host_id, first_seen, last_seen, version)| {
            json!({
                "host_id": host_id,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "version": version,
                "queue_len": 0,
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::build_app;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn hb_body(host: &str, ts: i64, queue: u64) -> String {
        serde_json::json!({
            "host_id": host,
            "ts": ts,
            "version": "0.1.0",
            "queue_len": queue
        })
        .to_string()
    }

    #[tokio::test]
    async fn heartbeat_registers_host_and_lists_it() {
        let app = build_app(AppState::for_tests().await).await;
        let send = |app: axum::Router, body: String| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/heartbeat")
                        .header("content-type", "application/json")
                        .header("authorization", "Bearer test-token")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };
        let resp = send(app.clone(), hb_body("h-1", 1000, 0)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = send(app.clone(), hb_body("h-1", 2000, 2)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/hosts")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let hosts = json["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["host_id"], "h-1");
        assert_eq!(hosts[0]["last_seen"], 2000);
        assert_eq!(hosts[0]["first_seen"], 1000);
        assert_eq!(hosts[0]["queue_len"], 0);
    }

    #[tokio::test]
    async fn hosts_list_requires_auth() {
        let app = build_app(AppState::for_tests().await).await;
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/hosts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
