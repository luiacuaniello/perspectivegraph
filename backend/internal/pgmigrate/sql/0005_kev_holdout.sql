-- Sealed KEV/EPSS forecasts awaiting their grading date.
--
-- The holdout works by SEALING a prediction before the outcome is known and grading it
-- only once the window has passed. That is what makes it evidence rather than a
-- retrospective story - and it only holds if the seal survives. A forecast that vanished
-- with a pod, or was written twice by two replicas, would be graded against a window
-- neither the operator nor the engine chose.
--
-- One row per (tenant, CVE): a CVE is sealed once and graded once.

CREATE TABLE IF NOT EXISTS kev_holdout (
    tenant    text        NOT NULL,
    cve       text        NOT NULL,
    predicted double precision NOT NULL,
    epss      double precision NOT NULL,
    basis     text        NOT NULL DEFAULT '',
    sealed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant, cve)
);

-- "Which forecasts are due?" is the only read, and it is by seal time.
CREATE INDEX IF NOT EXISTS kev_holdout_sealed ON kev_holdout (sealed_at);
