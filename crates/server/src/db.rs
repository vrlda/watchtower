use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

/// Connect to the configured database with WAL journaling (concurrent
/// reader + writer without lock contention).
pub async fn connect(cfg: &crate::config::ServerConfig) -> Result<sqlx::SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(&cfg.db_url)
        .map_err(|e| sqlx::Error::Configuration(Box::new(e)))?
        .journal_mode(SqliteJournalMode::Wal)
        .create_if_missing(true);
    SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
}

/// Apply the schema. Idempotent — safe to run on every startup.
pub async fn init_schema(pool: &sqlx::SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hosts (
            host_id    TEXT PRIMARY KEY,
            first_seen INTEGER NOT NULL,
            last_seen  INTEGER NOT NULL,
            version    TEXT NOT NULL DEFAULT ''
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS events (
            id            TEXT PRIMARY KEY,
            ts            INTEGER NOT NULL,
            host_id       TEXT NOT NULL,
            key           TEXT NOT NULL,
            kind          TEXT NOT NULL,
            severity      TEXT NOT NULL,
            summary       TEXT NOT NULL,
            evidence_json TEXT NOT NULL DEFAULT '[]',
            created_at    INTEGER NOT NULL -- server ingest time; NEVER used for ordering
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_host_ts ON events (host_id, ts DESC)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_kind ON events (kind)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts)")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS incidents (
            id         TEXT PRIMARY KEY,
            key        TEXT NOT NULL,
            host_id    TEXT NOT NULL DEFAULT '',
            severity   TEXT NOT NULL,
            status     TEXT NOT NULL DEFAULT 'open',
            headline   TEXT NOT NULL,
            cause      TEXT NOT NULL DEFAULT '',
            actions_json TEXT NOT NULL DEFAULT '[]',
            affected_json TEXT NOT NULL DEFAULT '[]',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            acked_at   INTEGER,
            resolved_at INTEGER
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_incidents_key ON incidents (key, status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents (created_at DESC)")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_key_open ON incidents (key) WHERE status != 'resolved'",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS incident_events (
            incident_id TEXT NOT NULL,
            event_id    TEXT NOT NULL,
            PRIMARY KEY (incident_id, event_id)
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_incident_events_event ON incident_events (event_id)",
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> sqlx::SqlitePool {
        sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn schema_initializes_and_is_idempotent() {
        let pool = test_pool().await;
        init_schema(&pool).await.unwrap();
        init_schema(&pool).await.unwrap();
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM sqlite_master WHERE type='table'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(
            n >= 4,
            "hosts, events, incidents, incident_events tables exist"
        );
    }
}
