ALTER TABLE scans
ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;

ALTER TABLE scans
ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;

ALTER TABLE scans
ADD COLUMN IF NOT EXISTS result JSONB;

ALTER TABLE scans
ADD COLUMN IF NOT EXISTS error_message TEXT;

ALTER TABLE scans
ADD COLUMN IF NOT EXISTS worker_attempts INTEGER NOT NULL DEFAULT 0;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'scans_worker_attempts_nonnegative'
    ) THEN
        ALTER TABLE scans
        ADD CONSTRAINT scans_worker_attempts_nonnegative
        CHECK (worker_attempts >= 0);
    END IF;
END
$$;