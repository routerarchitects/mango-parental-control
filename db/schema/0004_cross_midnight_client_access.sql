-- 0004_cross_midnight_client_access.sql
-- Enable ISO-8601 timestamps and cross-midnight client-access time windows

ALTER TABLE pc_client_access
    ADD COLUMN IF NOT EXISTS starts_at  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

ALTER TABLE pc_client_access
    DROP CONSTRAINT IF EXISTS chk_pc_client_access_stop_date,
    DROP CONSTRAINT IF EXISTS chk_pc_client_access_stop_time,
    DROP CONSTRAINT IF EXISTS chk_pc_client_access_boundary;

ALTER TABLE pc_client_access
    ALTER COLUMN start_date TYPE TEXT USING start_date::TEXT,
    ALTER COLUMN stop_date  TYPE TEXT USING stop_date::TEXT,
    ALTER COLUMN start_time TYPE TEXT USING start_time::TEXT,
    ALTER COLUMN stop_time  TYPE TEXT USING stop_time::TEXT;

ALTER TABLE pc_client_access
    ADD CONSTRAINT chk_pc_client_access_boundary CHECK (
        (start_date IS NULL AND stop_date IS NULL)
        OR
        (start_date IS NOT NULL AND stop_date IS NOT NULL)
    );

ALTER TABLE pc_client_access
    ADD CONSTRAINT chk_pc_client_access_timestamps CHECK (
        (starts_at IS NULL AND expires_at IS NULL)
        OR
        (expires_at > starts_at)
    );

CREATE INDEX IF NOT EXISTS idx_pc_client_access_expires_at 
    ON pc_client_access (expires_at) 
    WHERE expires_at IS NOT NULL;
