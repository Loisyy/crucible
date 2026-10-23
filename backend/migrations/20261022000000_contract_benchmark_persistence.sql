-- Migration for persisting contract benchmark runs and baselines (#1212)
-- Enables historical regression tracking and latency trend queries across restarts.

CREATE TABLE IF NOT EXISTS contract_benchmark_runs (
    id UUID PRIMARY KEY,
    contract_id TEXT NOT NULL,
    benchmark_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('passed', 'warning', 'failed')),
    sample_count BIGINT NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    overall_metrics JSONB NOT NULL,
    operations JSONB NOT NULL DEFAULT '[]',
    regressions JSONB NOT NULL DEFAULT '[]',
    baseline_metrics JSONB
);

CREATE INDEX IF NOT EXISTS idx_benchmark_runs_contract_generated
    ON contract_benchmark_runs (contract_id, generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_benchmark_runs_name_generated
    ON contract_benchmark_runs (benchmark_name, generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_benchmark_runs_status
    ON contract_benchmark_runs (status);

CREATE TABLE IF NOT EXISTS contract_benchmark_baselines (
    contract_id TEXT NOT NULL,
    benchmark_name TEXT NOT NULL,
    p95_duration_us BIGINT NOT NULL,
    avg_cpu_instructions DOUBLE PRECISION NOT NULL,
    peak_memory_bytes BIGINT NOT NULL,
    avg_resource_fee_stroops DOUBLE PRECISION NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (contract_id, benchmark_name)
);

CREATE INDEX IF NOT EXISTS idx_benchmark_baselines_lookup
    ON contract_benchmark_baselines (contract_id, benchmark_name);
