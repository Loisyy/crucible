//! SCHEDULER APPROACH: Option B — Custom Tokio interval loop with cron crate
//! Rationale: We require strict control over execution guarantees such as distributed locking, timeouts, retries, and history logging. A custom loop using `tokio::time::sleep_until` and the `cron` crate allows us to wrap the execution precisely in a Redis lock and accurately handle timeouts using `tokio::time::timeout`.

use async_trait::async_trait;
use tracing::{info, instrument};

use crate::workers::error::JobError;
use crate::workers::job_history::cleanup_old_runs;
use crate::workers::scheduler::{JobContext, JobHandler};

/// A job that tests database and Redis connectivity.
pub struct HealthCheckJob;

#[async_trait]
impl JobHandler for HealthCheckJob {
    #[instrument(skip_all, fields(job_name = ctx.job_name))]
    async fn run(&self, ctx: JobContext) -> Result<(), JobError> {
        info!("Running health check job");

        // Ping Database
        sqlx::query("SELECT 1")
            .execute(&ctx.pool)
            .await
            .map_err(JobError::DatabaseError)?;
        info!("PostgreSQL connection is healthy");

        // Ping Redis
        let mut redis_conn = ctx
            .redis
            .get_async_connection()
            .await
            .map_err(JobError::RedisError)?;
        redis::cmd("PING")
            .query_async::<String>(&mut redis_conn)
            .await
            .map_err(JobError::RedisError)?;
        info!("Redis connection is healthy");

        Ok(())
    }
}

/// A job that cleans up old job history runs.
pub struct CleanupJob {
    pub retain_days: i64,
}

#[async_trait]
impl JobHandler for CleanupJob {
    #[instrument(skip_all, fields(job_name = ctx.job_name))]
    async fn run(&self, ctx: JobContext) -> Result<(), JobError> {
        info!(
            "Running job history cleanup job (retention: {} days)",
            self.retain_days
        );

        let deleted_count = cleanup_old_runs(&ctx.pool, self.retain_days).await?;
        info!("Cleaned up {} old job run records", deleted_count);

        Ok(())
    }
}

/// A scheduled job that executes hourly and daily pre-aggregated activity rollups (#1222).
pub struct AnalyticsRollupJob;

#[async_trait]
impl JobHandler for AnalyticsRollupJob {
    #[instrument(skip_all, fields(job_name = ctx.job_name))]
    async fn run(&self, ctx: JobContext) -> Result<(), JobError> {
        info!("Running contract analytics historical rollup job");
        let aggregator =
            crate::services::analytics_aggregator::AnalyticsAggregator::new(ctx.pool, ctx.redis);
        let now = chrono::Utc::now();
        let one_day_ago = now - chrono::Duration::hours(24);

        let hourly_rows = aggregator
            .aggregate_hourly_rollups(one_day_ago, now)
            .await
            .map_err(JobError::DatabaseError)?;

        let yesterday = (now - chrono::Duration::days(1)).date_naive();
        let daily_rows = aggregator
            .aggregate_daily_rollups(yesterday)
            .await
            .map_err(JobError::DatabaseError)?;

        info!(
            hourly_rows_updated = hourly_rows,
            daily_rows_updated = daily_rows,
            "Contract analytics rollups completed successfully"
        );
        Ok(())
    }
}

/// A scheduled job that executes automated partitioning and TTL retention pruning for contract call logs (#1217).
pub struct ContractCallLogsRetentionJob {
    pub policy: crate::services::contract_call_logger::LogRetentionPolicy,
}

impl Default for ContractCallLogsRetentionJob {
    fn default() -> Self {
        Self {
            policy: crate::services::contract_call_logger::LogRetentionPolicy::default(),
        }
    }
}

#[async_trait]
impl JobHandler for ContractCallLogsRetentionJob {
    #[instrument(skip_all, fields(job_name = ctx.job_name))]
    async fn run(&self, ctx: JobContext) -> Result<(), JobError> {
        info!("Running contract call logs retention and partitioning job");
        let logger = crate::services::contract_call_logger::ContractCallLogger::new(ctx.pool);
        let report = logger
            .run_retention_maintenance(&self.policy)
            .await
            .map_err(|e| JobError::HandlerPanic(e.to_string()))?;
        info!(
            purged_records = report.purged_records_count,
            created_partitions = ?report.created_partitions,
            dropped_partitions = ?report.dropped_partitions,
            "Contract call logs retention maintenance completed successfully"
        );
        Ok(())
    }
}
