ALTER TABLE scans
ADD COLUMN IF NOT EXISTS user_id UUID;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'scans_user_id_fkey'
    ) THEN
        ALTER TABLE scans
        ADD CONSTRAINT scans_user_id_fkey
        FOREIGN KEY (user_id)
        REFERENCES users(id);
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS scans_user_created_at_index
ON scans (user_id, created_at DESC);