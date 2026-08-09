-- Remediation tickets: who owns closing a given attack path, and whether they have.
--
-- Same reasoning as suppressions - a second replica must see the first's work, or two
-- engineers open two tickets for one path and each believes the other's is theirs.
--
-- The status is a CHECK rather than an enum type: an enum needs its own migration to
-- gain a value, and this list will grow.

CREATE TABLE IF NOT EXISTS tickets (
    id           text        PRIMARY KEY,
    tenant       text        NOT NULL,
    path_id      text        NOT NULL,
    title        text        NOT NULL DEFAULT '',
    route        text        NOT NULL DEFAULT '',
    owner        text        NOT NULL,
    status       text        NOT NULL CHECK (status IN ('open', 'closed')),
    external_url text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL,
    closed_at    timestamptz
);

-- "Is there already an open ticket for this path?" is asked before every create, and is
-- the only hot read.
CREATE INDEX IF NOT EXISTS tickets_open_for_path
    ON tickets (tenant, path_id) WHERE status = 'open';

CREATE INDEX IF NOT EXISTS tickets_tenant_created
    ON tickets (tenant, created_at DESC);
