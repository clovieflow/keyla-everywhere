//! Redis-backed admission: one atomic Lua reserve/reconcile/release agreement
//! shared by every gateway instance.
//!
//! The scripts are the same algorithm as the TypeScript gateway: a sliding RPM
//! window, pre-credited token budgets, and concurrency slots recorded in a
//! lease hash so release reverses exactly what reserve charged.

use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Script};

pub const LEASE_TTL_MS: i64 = 3_600_000;
pub const LEASE_KEY_TTL_SECONDS: i64 = 3_720;
pub const DAILY_COUNTER_TTL_SECONDS: i64 = 1_728_000 / 10;
pub const MONTHLY_COUNTER_TTL_SECONDS: i64 = 3_024_000;
pub const LIFETIME_COUNTER_TTL_SECONDS: i64 = 3_024_000;
pub const RPM_WINDOW_TTL_SECONDS: i64 = 65;
pub const CONCURRENCY_TTL_SECONDS: i64 = LEASE_KEY_TTL_SECONDS;

const RESERVE_SCRIPT_SOURCE: &str = r#"
local state = redis.call('HGET', KEYS[6], 'state')
if state == 'active' or state == 'committed' or state == 'released' then return 1 end
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', tonumber(ARGV[1]) - 60000)
local rpm = redis.call('ZCARD', KEYS[1])
local daily = tonumber(redis.call('GET', KEYS[2]) or '0')
local monthly = tonumber(redis.call('GET', KEYS[3]) or '0')
local concurrent = tonumber(redis.call('GET', KEYS[4]) or '0')
local tenantConcurrent = tonumber(redis.call('GET', KEYS[7]) or '0')
local lifetime = 0
if tonumber(ARGV[6]) then
  local rawLifetime = redis.call('GET', KEYS[5])
  lifetime = rawLifetime and tonumber(rawLifetime) or tonumber(ARGV[9])
  if not lifetime then return -99 end
  if not rawLifetime then redis.call('SET', KEYS[5], lifetime, 'EX', 3024000) end
end
local estimated = tonumber(ARGV[2])
if not estimated or estimated < 0 then return -99 end
if tonumber(ARGV[3]) and rpm >= tonumber(ARGV[3]) then return -1 end
if tonumber(ARGV[4]) and daily + estimated > tonumber(ARGV[4]) then return -2 end
if tonumber(ARGV[5]) and monthly + estimated > tonumber(ARGV[5]) then return -3 end
if tonumber(ARGV[6]) and lifetime + estimated > tonumber(ARGV[6]) then return -4 end
if tonumber(ARGV[7]) and concurrent >= tonumber(ARGV[7]) then return -5 end
if tonumber(ARGV[10]) and tenantConcurrent >= tonumber(ARGV[10]) then return -6 end
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[8])
redis.call('EXPIRE', KEYS[1], 65)
if tonumber(ARGV[4]) then redis.call('INCRBY', KEYS[2], estimated); redis.call('EXPIRE', KEYS[2], 172800) end
if tonumber(ARGV[5]) then redis.call('INCRBY', KEYS[3], estimated); redis.call('EXPIRE', KEYS[3], 3024000) end
if tonumber(ARGV[6]) then redis.call('INCRBY', KEYS[5], estimated); redis.call('EXPIRE', KEYS[5], 3024000) end
if tonumber(ARGV[7]) then redis.call('INCR', KEYS[4]); redis.call('EXPIRE', KEYS[4], 3720) end
if tonumber(ARGV[10]) then redis.call('INCR', KEYS[7]); redis.call('EXPIRE', KEYS[7], 3720) end
redis.call('HSET', KEYS[6], 'state', 'active', 'reserved', estimated, 'daily', tonumber(ARGV[4]) and KEYS[2] or '', 'monthly', tonumber(ARGV[5]) and KEYS[3] or '', 'lifetime', tonumber(ARGV[6]) and KEYS[5] or '', 'concurrent', tonumber(ARGV[7]) and '1' or '0', 'tenant_concurrent', tonumber(ARGV[10]) and '1' or '0', 'tenant_id', ARGV[11], 'api_key_id', ARGV[12], 'expires_at', tonumber(ARGV[1]) + tonumber(ARGV[13]))
redis.call('EXPIRE', KEYS[6], tonumber(ARGV[14]))
return 0
"#;

const RECONCILE_SCRIPT_SOURCE: &str = r#"
local state = redis.call('HGET', KEYS[1], 'state')
if state == 'committed' or state == 'released' then return 1 end
if state ~= 'active' then return -99 end
local reserved = tonumber(redis.call('HGET', KEYS[1], 'reserved'))
local actual = tonumber(ARGV[1])
if not reserved or not actual or reserved < 0 or actual < 0 or reserved ~= math.floor(reserved) or actual ~= math.floor(actual) then return -99 end
local delta = actual - reserved
local updates = {}
for _, field in ipairs({'daily', 'monthly', 'lifetime'}) do
  local key = redis.call('HGET', KEYS[1], field)
  if key and key ~= '' then
    local value = tonumber(redis.call('GET', key))
    if not value or value < 0 or value + delta < 0 or value + delta ~= math.floor(value + delta) then return -99 end
    table.insert(updates, key)
  end
end
local concurrentKey = 'admission:concurrent:' .. ARGV[2]
local hasConcurrency = redis.call('HGET', KEYS[1], 'concurrent') == '1'
if hasConcurrency then
  local value = tonumber(redis.call('GET', concurrentKey))
  if not value or value < 1 or value ~= math.floor(value) then return -99 end
end
local tenantKey = ''
local hasTenantConcurrency = redis.call('HGET', KEYS[1], 'tenant_concurrent') == '1'
if hasTenantConcurrency then
  local tenantId = redis.call('HGET', KEYS[1], 'tenant_id')
  if not tenantId or tenantId == '' then return -99 end
  tenantKey = 'admission:tenant_concurrent:' .. tenantId
  local value = tonumber(redis.call('GET', tenantKey))
  if not value or value < 1 or value ~= math.floor(value) then return -99 end
end
for _, key in ipairs(updates) do redis.call('INCRBY', key, delta) end
if hasConcurrency then redis.call('DECR', concurrentKey) end
if hasTenantConcurrency then redis.call('DECR', tenantKey) end
redis.call('HSET', KEYS[1], 'state', 'committed', 'actual', actual)
return 0
"#;

const RELEASE_SCRIPT_SOURCE: &str = r#"
local state = redis.call('HGET', KEYS[1], 'state')
if state == 'released' or state == 'committed' then return 1 end
if state ~= 'active' then return -99 end
local reserved = tonumber(redis.call('HGET', KEYS[1], 'reserved'))
if not reserved or reserved < 0 then return -99 end
for _, field in ipairs({'daily', 'monthly', 'lifetime'}) do local key = redis.call('HGET', KEYS[1], field); if key and key ~= '' then local value = tonumber(redis.call('GET', key) or '0'); if not value or value < reserved then return -99 end; redis.call('DECRBY', key, reserved) end end
if redis.call('HGET', KEYS[1], 'concurrent') == '1' then local key = 'admission:concurrent:' .. ARGV[1]; local value = tonumber(redis.call('GET', key) or '0'); if not value or value < 1 then return -99 end; redis.call('DECR', key) end
if redis.call('HGET', KEYS[1], 'tenant_concurrent') == '1' then local tenantId = redis.call('HGET', KEYS[1], 'tenant_id'); if not tenantId or tenantId == '' then return -99 end; local key = 'admission:tenant_concurrent:' .. tenantId; local value = tonumber(redis.call('GET', key) or '0'); if not value or value < 1 then return -99 end; redis.call('DECR', key) end
redis.call('HSET', KEYS[1], 'state', 'released')
return 0
"#;

#[derive(Debug, Clone)]
pub struct AdmissionLimits {
    pub now_ms: i64,
    pub estimated_tokens: i64,
    pub rpm: Option<i64>,
    pub daily_tokens: Option<i64>,
    pub monthly_tokens: Option<i64>,
    pub lifetime_budget: Option<i64>,
    pub lifetime_consumed: i64,
    pub concurrency: Option<i64>,
    pub tenant_concurrency: Option<i64>,
    pub tenant_id: String,
    pub api_key_id: String,
}

#[derive(Debug, Clone)]
pub struct Reservation {
    pub id: String,
    pub api_key_id: String,
    pub estimated_tokens: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("admission store unavailable: {0}")]
    Unavailable(String),
    #[error("admission counter corrupt")]
    Corrupt,
    #[error("{0}")]
    Rejected(&'static str),
}

#[derive(Clone)]
pub struct RedisAdmission {
    connection: ConnectionManager,
}

impl RedisAdmission {
    pub async fn connect(url: &str) -> Result<Self, AdmissionError> {
        let client = redis::Client::open(url)
            .map_err(|error| AdmissionError::Unavailable(error.to_string()))?;
        let connection = ConnectionManager::new(client)
            .await
            .map_err(|error| AdmissionError::Unavailable(error.to_string()))?;
        Ok(Self { connection })
    }

    /// A live dependency check for readiness. The connection manager reconnects
    /// transparently, so a successful PING also proves the configured URL is
    /// still reachable.
    pub async fn ping(&self) -> bool {
        let mut connection = self.connection.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut connection)
            .await
            .is_ok()
    }

    fn daily_bucket(now_ms: i64) -> String {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms)
            .unwrap_or_else(chrono::Utc::now)
            .format("%Y-%m-%d")
            .to_string()
    }

    fn monthly_bucket(now_ms: i64) -> String {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms)
            .unwrap_or_else(chrono::Utc::now)
            .format("%Y-%m")
            .to_string()
    }

    pub async fn reserve(&self, limits: &AdmissionLimits) -> Result<Reservation, AdmissionError> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.subsec_nanos())
            .unwrap_or(0);
        let id = format!("{}:{}:{}", limits.api_key_id, limits.now_ms, nanos);
        let mut connection = self.connection.clone();
        let keys = vec![
            format!("admission:rpm:{}", limits.api_key_id),
            format!(
                "admission:daily:{}:{}",
                limits.api_key_id,
                Self::daily_bucket(limits.now_ms)
            ),
            format!(
                "admission:monthly:{}:{}",
                limits.api_key_id,
                Self::monthly_bucket(limits.now_ms)
            ),
            format!("admission:concurrent:{}", limits.api_key_id),
            format!("admission:lifetime:{}", limits.api_key_id),
            format!("admission:lease:{id}"),
            format!("admission:tenant_concurrent:{}", limits.tenant_id),
        ];
        let args = vec![
            limits.now_ms.to_string(),
            limits.estimated_tokens.to_string(),
            limits
                .rpm
                .map(|value| value.to_string())
                .unwrap_or_default(),
            limits
                .daily_tokens
                .map(|value| value.to_string())
                .unwrap_or_default(),
            limits
                .monthly_tokens
                .map(|value| value.to_string())
                .unwrap_or_default(),
            limits
                .lifetime_budget
                .map(|value| value.to_string())
                .unwrap_or_default(),
            limits
                .concurrency
                .map(|value| value.to_string())
                .unwrap_or_default(),
            id.clone(),
            limits.lifetime_consumed.to_string(),
            limits
                .tenant_concurrency
                .map(|value| value.to_string())
                .unwrap_or_default(),
            limits.tenant_id.clone(),
            limits.api_key_id.clone(),
            LEASE_TTL_MS.to_string(),
            LEASE_KEY_TTL_SECONDS.to_string(),
        ];
        let result: i64 = Script::new(RESERVE_SCRIPT_SOURCE)
            .key(keys)
            .arg(args)
            .invoke_async(&mut connection)
            .await
            .map_err(|error| AdmissionError::Unavailable(error.to_string()))?;
        match result {
            0 | 1 => Ok(Reservation {
                id,
                api_key_id: limits.api_key_id.clone(),
                estimated_tokens: limits.estimated_tokens,
            }),
            -99 => Err(AdmissionError::Corrupt),
            -1 => Err(AdmissionError::Rejected("rpm_exhausted")),
            -2 => Err(AdmissionError::Rejected("daily_token_limit")),
            -3 => Err(AdmissionError::Rejected("monthly_token_limit")),
            -4 => Err(AdmissionError::Rejected("lifetime_token_budget")),
            -5 => Err(AdmissionError::Rejected("concurrency_limit")),
            -6 => Err(AdmissionError::Rejected("tenant_capacity_exhausted")),
            _ => Err(AdmissionError::Corrupt),
        }
    }

    pub async fn reconcile(
        &self,
        reservation: &Reservation,
        actual_tokens: i64,
    ) -> Result<(), AdmissionError> {
        let mut connection = self.connection.clone();
        let result: i64 = Script::new(RECONCILE_SCRIPT_SOURCE)
            .key(format!("admission:lease:{}", reservation.id))
            .arg(actual_tokens.max(0))
            .arg(&reservation.api_key_id)
            .invoke_async(&mut connection)
            .await
            .map_err(|error| AdmissionError::Unavailable(error.to_string()))?;
        match result {
            0 | 1 => Ok(()),
            _ => Err(AdmissionError::Corrupt),
        }
    }

    pub async fn release(&self, reservation: &Reservation) -> Result<(), AdmissionError> {
        let mut connection = self.connection.clone();
        let result: i64 = Script::new(RELEASE_SCRIPT_SOURCE)
            .key(format!("admission:lease:{}", reservation.id))
            .arg(&reservation.api_key_id)
            .invoke_async(&mut connection)
            .await
            .map_err(|error| AdmissionError::Unavailable(error.to_string()))?;
        match result {
            0 | 1 => Ok(()),
            _ => Err(AdmissionError::Corrupt),
        }
    }

    /// Remaining lifetime counter, for diagnostics/tests.
    pub async fn lifetime(&self, api_key_id: &str) -> Result<Option<i64>, AdmissionError> {
        let mut connection = self.connection.clone();
        connection
            .get::<_, Option<i64>>(format!("admission:lifetime:{api_key_id}"))
            .await
            .map_err(|error| AdmissionError::Unavailable(error.to_string()))
    }
}
