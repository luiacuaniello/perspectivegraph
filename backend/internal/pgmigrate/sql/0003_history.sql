-- Temporal state: the lifecycle of each attack path, plus the posture and calibration
-- trends.
--
-- The multi-replica problem here is not the writes - the analyzer is leader-gated, so
-- only one process observes a pass - it is the READS. A replica that is not the leader
-- holds an empty in-memory history, so the trend chart is full or blank depending on
-- which pod answered. Putting it here makes every replica read the same series.

CREATE TABLE IF NOT EXISTS history_paths (
    tenant      text        NOT NULL,
    id          text        NOT NULL,
    route       text        NOT NULL DEFAULT '',
    score       double precision NOT NULL DEFAULT 0,
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    open        boolean     NOT NULL,
    resolved_at timestamptz,
    reopens     integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant, id)
);

-- "Which paths are open, and which is oldest" backs the MTTR panel.
CREATE INDEX IF NOT EXISTS history_paths_open ON history_paths (tenant, open);

CREATE TABLE IF NOT EXISTS history_posture (
    tenant         text        NOT NULL,
    at             timestamptz NOT NULL,
    critical_paths integer     NOT NULL,
    risk_pct       double precision NOT NULL,
    PRIMARY KEY (tenant, at)
);

CREATE TABLE IF NOT EXISTS history_calibration (
    tenant  text        NOT NULL,
    at      timestamptz NOT NULL,
    brier   double precision NOT NULL,
    ece     double precision NOT NULL,
    samples integer     NOT NULL,
    PRIMARY KEY (tenant, at)
);
