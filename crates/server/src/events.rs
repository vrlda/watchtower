use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::app::AppState;

#[derive(Deserialize, Default)]
pub struct EventQuery {
    host: Option<String>,
    kind: Option<String>,
    severity: Option<String>,
    since: Option<i64>,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    100
}

/// GET /v1/events — timeline. Order is (ts DESC, id) — NEVER arrival order:
/// agent batches contain non-monotonic, duplicate ts values (M1 final review
/// constraint); created_at must never be used for ordering.
pub async fn list_events(
    State(state): State<AppState>,
    Query(q): Query<EventQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let events = fetch_events(&state.pool, &q).await.map_err(|e| {
        eprintln!("events list failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(json!({ "events": events })))
}

pub async fn fetch_events(
    pool: &sqlx::SqlitePool,
    q: &EventQuery,
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let limit = q.limit.clamp(1, 1000);
    let rows = sqlx::query_as::<_, (String, i64, String, String, String, String, String)>(
        "SELECT id, ts, host_id, kind, severity, summary, evidence_json
         FROM events
         WHERE (?1 IS NULL OR host_id = ?1)
           AND (?2 IS NULL OR kind = ?2)
           AND (?3 IS NULL OR severity = ?3)
           AND (?4 IS NULL OR ts >= ?4)
         ORDER BY ts DESC, id
         LIMIT ?5",
    )
    .bind(q.host.as_deref())
    .bind(q.kind.as_deref())
    .bind(q.severity.as_deref())
    .bind(q.since)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, ts, host_id, kind, severity, summary, evidence_json)| {
                let evidence = serde_json::from_str::<serde_json::Value>(&evidence_json)
                    .unwrap_or_else(|_| json!([]));
                json!({
                    "id": id,
                    "ts": ts,
                    "host_id": host_id,
                    "kind": kind,
                    "severity": severity,
                    "summary": summary,
                    "evidence": evidence,
                })
            },
        )
        .collect())
}

/// Raw events since `since_ms`, oldest first — used by the correlation scan.
pub async fn fetch_events_simple(
    pool: &sqlx::SqlitePool,
    since_ms: i64,
) -> Result<Vec<wt_common::AgentEvent>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (String, i64, String, String, String, String, String, String)>(
        "SELECT id, ts, host_id, key, kind, severity, summary, evidence_json
         FROM events WHERE ts >= ?1 ORDER BY ts ASC, id",
    )
    .bind(since_ms)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(
            |(id, ts, host_id, key, kind, severity, summary, evidence_json)| {
                let kind = serde_json::from_str(&format!("\"{}\"", kind)).ok()?;
                let severity = serde_json::from_str(&format!("\"{}\"", severity)).ok()?;
                Some(wt_common::AgentEvent {
                    id,
                    ts,
                    host_id,
                    key,
                    kind,
                    severity,
                    summary,
                    evidence: serde_json::from_str(&evidence_json).unwrap_or_default(),
                })
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::build_app;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    use wt_common::{AgentEvent, EventKind, Severity};

    async fn seed(state: &AppState, id: &str, ts: i64, kind: EventKind, sev: Severity) {
        let ev = AgentEvent {
            id: id.into(),
            ts,
            host_id: "h-1".into(),
            key: format!("k:{}", id),
            kind,
            severity: sev,
            summary: format!("event {}", id),
            evidence: vec![wt_common::Evidence {
                ts,
                source: "test".into(),
                detail: "d".into(),
            }],
        };
        crate::ingest::store_events(&state.pool, &[ev])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn events_list_orders_by_ts_desc_and_returns_evidence() {
        let state = AppState::for_tests().await;
        seed(
            &state,
            "e-1",
            1000,
            EventKind::ServiceFailed,
            Severity::Critical,
        )
        .await;
        seed(&state, "e-2", 2000, EventKind::CpuSpike, Severity::Warning).await;
        seed(&state, "e-3", 1500, EventKind::MemHigh, Severity::Warning).await;
        let app = build_app(state).await;
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/events")
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
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["id"], "e-2"); // newest first
        assert_eq!(events[1]["id"], "e-3");
        assert_eq!(events[2]["id"], "e-1");
        assert_eq!(events[0]["evidence"][0]["source"], "test");
    }

    #[tokio::test]
    async fn events_filters_by_kind_and_limit() {
        let state = AppState::for_tests().await;
        seed(
            &state,
            "e-1",
            1000,
            EventKind::ServiceFailed,
            Severity::Critical,
        )
        .await;
        seed(&state, "e-2", 2000, EventKind::CpuSpike, Severity::Warning).await;
        let app = build_app(state).await;
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/events?kind=CpuSpike&limit=10")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["id"], "e-2");
    }

    #[tokio::test]
    async fn events_respect_since_and_host_filter() {
        let state = AppState::for_tests().await;
        seed(
            &state,
            "e-1",
            1000,
            EventKind::ServiceFailed,
            Severity::Critical,
        )
        .await;
        seed(&state, "e-2", 2000, EventKind::CpuSpike, Severity::Warning).await;
        let app = build_app(state).await;
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/events?host=h-1&since=1500")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["id"], "e-2");
    }

    #[tokio::test]
    async fn events_requires_auth() {
        let app = build_app(AppState::for_tests().await).await;
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
