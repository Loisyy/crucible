-- Pre-aggregated hourly and daily rollup tables for contract activity analytics (#1222)
CREATE TABLE IF NOT EXISTS contract_hourly_rollups (
    contract_id VARCHAR(255) NOT NULL,
    bucket_hour TIMESTAMPTZ NOT NULL,
    call_count BIGINT NOT NULL DEFAULT 0,
    error_count BIGINT NOT NULL DEFAULT 0,
    total_gas_used DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    unique_callers BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (contract_id, bucket_hour)
);

CREATE INDEX IF NOT EXISTS idx_contract_hourly_rollups_time ON contract_hourly_rollups(bucket_hour);

CREATE TABLE IF NOT EXISTS contract_daily_rollups (
    contract_id VARCHAR(255) NOT NULL,
    bucket_date DATE NOT NULL,
    call_count BIGINT NOT NULL DEFAULT 0,
    error_count BIGINT NOT NULL DEFAULT 0,
    total_gas_used DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    unique_callers BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (contract_id, bucket_date)
);

CREATE INDEX IF NOT EXISTS idx_contract_daily_rollups_date ON contract_daily_rollups(bucket_date);
