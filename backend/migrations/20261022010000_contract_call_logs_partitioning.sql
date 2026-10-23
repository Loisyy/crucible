-- Add declarative partitioning support and retention index for contract_call_logs (#1217)
CREATE INDEX IF NOT EXISTS idx_contract_call_logs_timestamp_retention ON contract_call_logs(timestamp DESC);
