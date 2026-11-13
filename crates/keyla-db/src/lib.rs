//! Pool, migration runner, and readiness for PostgreSQL.
//!
//! Port of `src/persistence/db-pg.ts`, `migrate.ts`, and `readiness.ts`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::{Connection, Row};
use thiserror::Error;

pub mod catalog;
pub mod dispatch;
pub mod seed;
pub mod snapshot;

pub const MIGRATION_LEDGER_TABLE: &str = "keyla_schema_migrations";
pub const LEDGER_LEGACY_TABLE: &str = "cartethyia_schema_migrations";
pub const LEDGER_DDL: &str = "CREATE TABLE IF NOT EXISTS keyla_schema_migrations (\n  migration_id text PRIMARY KEY,\n  applied_at timestamptz NOT NULL DEFAULT now()\n)";

#[derive(Debug, Error)]
pub enum DbError {
    #[error("{0}")]
    Config(String),
    #[error("Migration {migration_id} failed: {source}")]
    Migration {
        migration_id: String,
        #[source]
        source: sqlx::Error,
    },
    #[error("Migrations folder not found: {0}")]
    MigrationsFolder(String),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type DbResult<T> = Result<T, DbError>;

/// One checked-out connection URL source, in resolution order.
pub struct ConnectionUrlCandidate<'a> {
    pub source: &'a str,
    pub value: Option<String>,
}

fn database_url_candidates(env: &dyn keyla_config::Env) -> Vec<ConnectionUrlCandidate<'_>> {
    vec![
        ConnectionUrlCandidate {
            source: "DATABASE_URL",
            value: env.get("DATABASE_URL"),
        },
        ConnectionUrlCandidate {
            source: "DATABASE_PRIVATE_URL",
            value: env.get("DATABASE_PRIVATE_URL"),
        },
        ConnectionUrlCandidate {
            source: "DATABASE_PUBLIC_URL",
            value: env.get("DATABASE_PUBLIC_URL"),
        },
    ]
}

fn trimmed(env: &dyn keyla_config::Env, name: &str) -> Option<String> {
    env.get(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Assembles the standard libpq variable set into a URL, or `None` when it is
/// incomplete. `PGDATABASE` and `PGPASSWORD` are optional.
fn database_url_from_libpq_env(env: &dyn keyla_config::Env) -> Option<String> {
    let host = trimmed(env, "PGHOST")?;
    let port = trimmed(env, "PGPORT")?;
    let user = trimmed(env, "PGUSER");
    let password = env.get("PGPASSWORD").filter(|value| !value.is_empty());
    let database = trimmed(env, "PGDATABASE");
    let authority_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host
    };
    let credentials = match user {
        Some(user) => match password {
            Some(password) => format!(
                "{}:{}@",
                encode_component(&user),
                encode_component(&password)
            ),
            None => format!("{}@", encode_component(&user)),
        },
        None => String::new(),
    };
    let path = database
        .map(|database| format!("/{}", encode_component(&database)))
        .unwrap_or_default();
    Some(format!(
        "postgres://{credentials}{authority_host}:{port}{path}"
    ))
}

fn encode_component(value: &str) -> String {
    // `url`'s form encoding matches the Node helper for the characters a
    // database component can contain.
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Resolves the connection string from `DATABASE_URL`, the platform aliases,
/// or the libpq variable set.
pub fn require_database_url(env: &dyn keyla_config::Env) -> DbResult<String> {
    for candidate in database_url_candidates(env) {
        if let Some(value) = candidate.value {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            if value.starts_with("postgres://") || value.starts_with("postgresql://") {
                return Ok(value.to_owned());
            }
            return Err(DbError::Config(format!(
                "{} must be a postgres:// or postgresql:// URL",
                candidate.source
            )));
        }
    }
    if let Some(assembled) = database_url_from_libpq_env(env) {
        return Ok(assembled);
    }
    Err(DbError::Config(
        "No Postgres connection string is configured. Set DATABASE_URL to the full URL \
         (postgres://user:pass@host:5432/db). On Railway, reference the database service from \
         the app service's Variables tab (DATABASE_URL=${{ Postgres.DATABASE_URL }}), spelling \
         the service name exactly — a reference to a service that does not exist resolves to an \
         empty string. PGHOST, PGPORT, PGUSER, PGPASSWORD and PGDATABASE are accepted as an \
         alternative. Keyla never infers a Docker or Laragon connection automatically."
            .to_owned(),
    ))
}

/// `DATABASE_POOL_MAX` (positive integer), defaulting to the resource bound.
pub fn pool_max_from_env(env: &dyn keyla_config::Env) -> DbResult<u32> {
    match env.get("DATABASE_POOL_MAX") {
        None => Ok(20),
        Some(raw) => raw
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|value| *value >= 1)
            .ok_or_else(|| {
                DbError::Config(format!(
                    "DATABASE_POOL_MAX must be a positive integer (got \"{raw}\")"
                ))
            }),
    }
}

fn session_timeout(env: &dyn keyla_config::Env, name: &str, default: u64) -> u64 {
    env.get(name)
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

/// Opens the external PostgreSQL pool with the session tuning the runner
/// depends on.
pub async fn connect_pool(env: &dyn keyla_config::Env) -> DbResult<PgPool> {
    let url = require_database_url(env)?;
    let max = pool_max_from_env(env)?;
    let statement_timeout = session_timeout(env, "DATABASE_STATEMENT_TIMEOUT_MS", 30_000);
    let idle_timeout = session_timeout(env, "DATABASE_IDLE_IN_TXN_TIMEOUT_MS", 60_000);
    let lock_timeout = session_timeout(env, "DATABASE_LOCK_TIMEOUT_MS", 5_000);
    let connect_options = sqlx::postgres::PgConnectOptions::from_str(&url)?.options([
        ("statement_timeout", statement_timeout.to_string()),
        (
            "idle_in_transaction_session_timeout",
            idle_timeout.to_string(),
        ),
        ("lock_timeout", lock_timeout.to_string()),
    ]);
    let pool = PgPoolOptions::new()
        .max_connections(max)
        .idle_timeout(Some(Duration::from_secs(60)))
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(connect_options)
        .await?;
    Ok(pool)
}

/// The `<cwd>/migrations` directory, failing loudly when it is missing.
pub fn resolve_migrations_folder() -> DbResult<PathBuf> {
    let folder = std::env::current_dir()?.join("migrations");
    if !folder.is_dir() {
        return Err(DbError::MigrationsFolder(
            folder.to_string_lossy().into_owned(),
        ));
    }
    Ok(folder)
}

/// Numbered SQL files, sorted by filename.
pub fn migration_files(folder: &Path) -> DbResult<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(folder)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !path.is_file() {
            continue;
        }
        let bytes = name.as_bytes();
        let numbered = bytes.len() > 8
            && bytes[..4].iter().all(u8::is_ascii_digit)
            && bytes[4] == b'_'
            && name.ends_with(".sql");
        if numbered {
            files.push(path);
        }
    }
    files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    Ok(files)
}

/// Resolves which ledger holds this database's history. The choice is made on
/// row count so a failed partial boot cannot replay the schema.
pub async fn resolve_ledger_table(pool: &PgPool) -> DbResult<String> {
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename IN ($1, $2)",
    )
    .bind(MIGRATION_LEDGER_TABLE)
    .bind(LEDGER_LEGACY_TABLE)
    .fetch_all(pool)
    .await?;
    let present: Vec<String> = rows
        .iter()
        .map(|row| row.get::<String, _>("tablename"))
        .collect();
    if present.is_empty() {
        return Ok(MIGRATION_LEDGER_TABLE.to_owned());
    }
    let mut counts = Vec::new();
    for table in present {
        let count: i64 = sqlx::query_scalar(&format!("SELECT count(*)::bigint FROM {table}"))
            .fetch_one(pool)
            .await?;
        counts.push((table, count));
    }
    let current = counts
        .iter()
        .find(|(table, _)| table == MIGRATION_LEDGER_TABLE)
        .map(|(_, count)| *count)
        .unwrap_or(0);
    let legacy = counts
        .iter()
        .find(|(table, _)| table == LEDGER_LEGACY_TABLE)
        .map(|(_, count)| *count)
        .unwrap_or(0);
    Ok(if legacy > current {
        LEDGER_LEGACY_TABLE.to_owned()
    } else {
        MIGRATION_LEDGER_TABLE.to_owned()
    })
}

/// Every shipped migration, embedded so a single binary needs no source tree.
static EMBEDDED_MIGRATIONS: include_dir::Dir<'static> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/../../migrations");

fn embedded_migration_entries() -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = EMBEDDED_MIGRATIONS
        .files()
        .filter(|file| file.path().extension().and_then(|value| value.to_str()) == Some("sql"))
        .filter_map(|file| {
            let name = file.path().file_name()?.to_str()?.to_owned();
            let sql = file.contents_utf8()?.to_owned();
            Some((name, sql))
        })
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
}

/// Applies numbered SQL files in order under one cross-process advisory lock.
pub async fn apply_sql_migrations(pool: &PgPool, folder: &Path) -> DbResult<()> {
    let mut entries = Vec::new();
    for file in migration_files(folder)? {
        let name = file
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_owned();
        entries.push((name, tokio::fs::read_to_string(file).await?));
    }
    apply_migration_entries(pool, &entries).await
}

/// Applies the migrations embedded in the binary.
pub async fn apply_embedded_migrations(pool: &PgPool) -> DbResult<()> {
    apply_migration_entries(pool, &embedded_migration_entries()).await
}

async fn apply_migration_entries(pool: &PgPool, files: &[(String, String)]) -> DbResult<()> {
    let mut connection = pool.acquire().await?;
    sqlx::query("SELECT pg_advisory_lock(hashtext('keyla:migrations'))")
        .execute(&mut *connection)
        .await?;
    let result = apply_with_lock(&mut connection, files).await;
    let _ = sqlx::query("SELECT pg_advisory_unlock(hashtext('keyla:migrations'))")
        .execute(&mut *connection)
        .await;
    result
}

async fn apply_with_lock(
    connection: &mut sqlx::PgConnection,
    files: &[(String, String)],
) -> DbResult<()> {
    sqlx::raw_sql(LEDGER_DDL).execute(&mut *connection).await?;
    let ledger = resolve_ledger_table_on(&mut *connection).await?;
    let rows: Vec<(String,)> = sqlx::query_as(&format!("SELECT migration_id FROM {ledger}"))
        .fetch_all(&mut *connection)
        .await?;
    let mut applied: BTreeSet<String> = rows.into_iter().map(|(id,)| id).collect();

    for (migration_id, script) in files {
        if applied.contains(migration_id) {
            continue;
        }
        let mut transaction = connection.begin().await?;
        match sqlx::raw_sql(script).execute(&mut *transaction).await {
            Ok(_) => {
                sqlx::query(&format!("INSERT INTO {ledger} (migration_id) VALUES ($1)"))
                    .bind(migration_id)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
                applied.insert(migration_id.clone());
            }
            Err(source) => {
                let _ = transaction.rollback().await;
                return Err(DbError::Migration {
                    migration_id: migration_id.clone(),
                    source,
                });
            }
        }
    }
    Ok(())
}

async fn resolve_ledger_table_on(connection: &mut sqlx::PgConnection) -> DbResult<String> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename IN ($1, $2)",
    )
    .bind(MIGRATION_LEDGER_TABLE)
    .bind(LEDGER_LEGACY_TABLE)
    .fetch_all(&mut *connection)
    .await?;
    let present: Vec<String> = rows.into_iter().map(|(name,)| name).collect();
    if present.is_empty() {
        return Ok(MIGRATION_LEDGER_TABLE.to_owned());
    }
    let mut counts = Vec::new();
    for table in present {
        let count: i64 = sqlx::query_scalar(&format!("SELECT count(*)::bigint FROM {table}"))
            .fetch_one(&mut *connection)
            .await?;
        counts.push((table, count));
    }
    let current = counts
        .iter()
        .find(|(table, _)| table == MIGRATION_LEDGER_TABLE)
        .map(|(_, count)| *count)
        .unwrap_or(0);
    let legacy = counts
        .iter()
        .find(|(table, _)| table == LEDGER_LEGACY_TABLE)
        .map(|(_, count)| *count)
        .unwrap_or(0);
    Ok(if legacy > current {
        LEDGER_LEGACY_TABLE.to_owned()
    } else {
        MIGRATION_LEDGER_TABLE.to_owned()
    })
}
// ─── Readiness ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessStatus {
    Ready,
    NotReady,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessCheckResult {
    pub status: ReadinessStatus,
    pub db: bool,
    pub migrations_applied: bool,
    pub redis: bool,
    pub reason: Option<&'static str>,
}

impl ReadinessCheckResult {
    pub fn ready() -> Self {
        Self {
            status: ReadinessStatus::Ready,
            db: true,
            migrations_applied: true,
            redis: true,
            reason: None,
        }
    }
}

/// One uncached readiness probe over the pool and the migration ledger.
pub async fn check_readiness(pool: &PgPool, folder: &Path, redis_ok: bool) -> ReadinessCheckResult {
    let timeout = Duration::from_secs(5);
    match tokio::time::timeout(timeout, sqlx::query("SELECT 1").execute(pool)).await {
        Ok(Ok(_)) => {}
        _ => {
            return ReadinessCheckResult {
                status: ReadinessStatus::NotReady,
                db: false,
                migrations_applied: false,
                redis: false,
                reason: Some("database not connected"),
            };
        }
    }

    let applied = match tokio::time::timeout(timeout, ledger_status(pool, folder)).await {
        Ok(Ok(applied)) => applied,
        _ => false,
    };
    if !applied {
        return ReadinessCheckResult {
            status: ReadinessStatus::NotReady,
            db: true,
            migrations_applied: false,
            redis: false,
            reason: Some("migrations not yet applied"),
        };
    }

    if !redis_ok {
        return ReadinessCheckResult {
            status: ReadinessStatus::NotReady,
            db: true,
            migrations_applied: true,
            redis: false,
            reason: Some("redis not connected"),
        };
    }

    ReadinessCheckResult::ready()
}

/// Compares the migration files on disk against the applied-migration ledger.
pub async fn ledger_status_embedded(pool: &PgPool) -> DbResult<bool> {
    let expected: Vec<String> = embedded_migration_entries()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    let ledger = resolve_ledger_table(pool).await?;
    let rows: Vec<(String,)> = sqlx::query_as(&format!("SELECT migration_id FROM {ledger}"))
        .fetch_all(pool)
        .await?;
    let applied: BTreeSet<String> = rows.into_iter().map(|(id,)| id).collect();
    Ok(expected.iter().all(|migration| applied.contains(migration)))
}

pub async fn ledger_status(pool: &PgPool, folder: &Path) -> DbResult<bool> {
    let expected: Vec<String> = migration_files(folder)?
        .into_iter()
        .filter_map(|file| {
            file.file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .collect();
    let ledger = resolve_ledger_table(pool).await?;
    let rows: Vec<(String,)> = sqlx::query_as(&format!("SELECT migration_id FROM {ledger}"))
        .fetch_all(pool)
        .await?;
    let applied: BTreeSet<String> = rows.into_iter().map(|(id,)| id).collect();
    Ok(expected.iter().all(|migration| applied.contains(migration)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyla_config::MapEnv;

    #[test]
    fn missing_database_url_fails_with_guidance() {
        let env = MapEnv::new();
        let error = require_database_url(&env).unwrap_err();
        assert!(error.to_string().contains("DATABASE_URL"));
        assert!(error.to_string().contains("Railway"));
    }

    #[test]
    fn platform_aliases_are_honoured_in_order() {
        let env = MapEnv::new()
            .set("DATABASE_PRIVATE_URL", "postgres://private/db")
            .set("DATABASE_PUBLIC_URL", "postgres://public/db");
        assert_eq!(require_database_url(&env).unwrap(), "postgres://private/db");

        let env = env.set("DATABASE_URL", "postgresql://primary/db");
        assert_eq!(
            require_database_url(&env).unwrap(),
            "postgresql://primary/db"
        );
    }

    #[test]
    fn libpq_variables_assemble_a_url() {
        let env = MapEnv::new()
            .set("PGHOST", "db.internal")
            .set("PGPORT", "5432")
            .set("PGUSER", "user name")
            .set("PGPASSWORD", "p@ss")
            .set("PGDATABASE", "keyla");
        assert_eq!(
            require_database_url(&env).unwrap(),
            "postgres://user+name:p%40ss@db.internal:5432/keyla"
        );
    }

    #[test]
    fn pool_max_is_validated() {
        assert_eq!(pool_max_from_env(&MapEnv::new()).unwrap(), 20);
        assert_eq!(
            pool_max_from_env(&MapEnv::new().set("DATABASE_POOL_MAX", "5")).unwrap(),
            5
        );
        assert!(pool_max_from_env(&MapEnv::new().set("DATABASE_POOL_MAX", "0")).is_err());
    }

    #[test]
    fn migration_files_are_sorted_and_numbered() {
        let folder = tempfile::tempdir().unwrap();
        for name in ["0001_b.sql", "0000_a.sql", "README.md", "12_c.sql"] {
            std::fs::write(folder.path().join(name), "-- noop").unwrap();
        }
        let names: Vec<String> = migration_files(folder.path())
            .unwrap()
            .into_iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["0000_a.sql", "0001_b.sql"]);
    }
}
