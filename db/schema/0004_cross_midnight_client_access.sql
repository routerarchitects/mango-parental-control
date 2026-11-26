-- 0004_cross_midnight_client_access.sql
-- Enable ISO-8601 timestamps and cross-midnight client-access time windows

ALTER TABLE pc_client_access
    ADD COLUMN IF NOT EXISTS starts_at  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

ALTER TABLE pc_client_access
    DROP CONSTRAINT IF EXISTS chk_pc_client_access_stop_date,
    DROP CONSTRAINT IF EXISTS chk_pc_client_access_stop_time,
    DROP CONSTRAINT IF EXISTS chk_pc_client_access_boundary,
    DROP CONSTRAINT IF EXISTS chk_pc_client_access_timestamps;

ALTER TABLE pc_client_access
    ALTER COLUMN start_date TYPE TEXT USING CASE WHEN start_date IS NOT NULL THEN to_char(start_date, 'YYYY-MM-DD') END,
    ALTER COLUMN stop_date  TYPE TEXT USING CASE WHEN stop_date  IS NOT NULL THEN to_char(stop_date,  'YYYY-MM-DD') END,
    ALTER COLUMN start_time TYPE TEXT USING CASE WHEN start_time IS NOT NULL THEN to_char(start_time, 'HH24:MI:SS') END,
    ALTER COLUMN stop_time  TYPE TEXT USING CASE WHEN stop_time  IS NOT NULL THEN to_char(stop_time,  'HH24:MI:SS') END;

-- Backfill existing legacy 4-field timed rows with explicit UTC TIMESTAMPTZ boundaries
UPDATE pc_client_access
SET
    starts_at  = (start_date || 'T' || start_time)::TIMESTAMP AT TIME ZONE 'UTC',
    expires_at = (start_date || 'T' || stop_time)::TIMESTAMP AT TIME ZONE 'UTC'
WHERE start_date IS NOT NULL
  AND stop_date  IS NOT NULL
  AND start_time IS NOT NULL
  AND stop_time  IS NOT NULL
  AND start_date ~ '^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$'
  AND stop_date  ~ '^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$'
  AND start_time ~ '^([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$'
  AND stop_time  ~ '^([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$'
  AND stop_time > start_time
  AND starts_at  IS NULL
  AND expires_at IS NULL;

-- Guard against PostgreSQL 3-valued logic (NULL evaluating to UNKNOWN):
-- either both timestamps are NULL or both are explicitly NOT NULL with expires_at > starts_at.
ALTER TABLE pc_client_access
    ADD CONSTRAINT chk_pc_client_access_timestamps CHECK (
        (starts_at IS NULL AND expires_at IS NULL)
        OR
        (starts_at IS NOT NULL AND expires_at IS NOT NULL AND expires_at > starts_at)
    );

-- Enforce the three valid client-access row shapes:
-- 1. Permanent: all 6 boundary/timestamp columns NULL
-- 2. Legacy 4-field timed: YYYY-MM-DD dates + HH:MM:SS times (stop_time > start_time);
--    starts_at/expires_at either both NOT NULL (expires_at > starts_at) or both NULL (legacy fallback allowance)
-- 3. Two-field ISO timed: canonical YYYY-MM-DDTHH:MM:SS dates (stop_date > start_date),
--    start_time/stop_time NULL, and starts_at/expires_at both NOT NULL (expires_at > starts_at)
ALTER TABLE pc_client_access
    ADD CONSTRAINT chk_pc_client_access_boundary CHECK (
        (
            start_date IS NULL
            AND stop_date IS NULL
            AND start_time IS NULL
            AND stop_time IS NULL
            AND starts_at IS NULL
            AND expires_at IS NULL
        )
        OR
        (
            start_date IS NOT NULL
            AND stop_date IS NOT NULL
            AND start_time IS NOT NULL
            AND stop_time IS NOT NULL
            AND start_date ~ '^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$'
            AND stop_date  ~ '^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$'
            AND start_time ~ '^([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$'
            AND stop_time  ~ '^([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$'
            AND stop_time > start_time
            AND (
                (starts_at IS NULL AND expires_at IS NULL)
                OR
                (starts_at IS NOT NULL AND expires_at IS NOT NULL AND expires_at > starts_at)
            )
        )
        OR
        (
            start_date IS NOT NULL
            AND stop_date IS NOT NULL
            AND start_time IS NULL
            AND stop_time IS NULL
            AND start_date ~ '^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$'
            AND stop_date  ~ '^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$'
            AND stop_date > start_date
            AND starts_at IS NOT NULL
            AND expires_at IS NOT NULL
            AND expires_at > starts_at
        )
    );

CREATE INDEX IF NOT EXISTS idx_pc_client_access_expires_at 
    ON pc_client_access (expires_at) 
    WHERE expires_at IS NOT NULL;
