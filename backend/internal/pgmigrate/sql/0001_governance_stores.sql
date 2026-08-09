-- Governance state that must be shared by every replica.
--
-- These records used to live in JSON files on a ReadWriteOnce volume, which is why the
-- chart refused to render with more than one backend replica: two writers would have
-- split-brained them, and an RWO volume cannot be co-mounted anyway. Moving them here
-- removes the single-replica ceiling.
--
-- The tenant is part of every primary key rather than a filter applied afterwards. The
-- isolation is then the database's job, not the caller's, and a query that forgets to
-- scope itself cannot silently read another tenant's decisions.

CREATE TABLE IF NOT EXISTS suppressions (
    tenant     text        NOT NULL,
    path_id    text        NOT NULL,
    reason     text        NOT NULL,
    owner      text        NOT NULL,
    note       text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    -- NULL means no expiry, which is why this is nullable rather than a sentinel date:
    -- a far-future timestamp standing in for "never" is the kind of thing that expires
    -- unexpectedly in 2038, and reads as an ordinary date to anyone auditing the table.
    expires_at timestamptz,
    PRIMARY KEY (tenant, path_id)
);

-- The board asks "which suppressions are in force for this tenant right now" on every
-- pass, and that is the only hot read.
CREATE INDEX IF NOT EXISTS suppressions_tenant_expiry
    ON suppressions (tenant, expires_at);
