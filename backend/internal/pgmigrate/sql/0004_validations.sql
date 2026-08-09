-- Red-team / BAS verdicts: the evidence every calibration number is computed from.
--
-- This is the most consequential table in the set. A suppression that goes missing is
-- noisy; a verdict that goes missing changes what the engine claims about its own
-- accuracy, and nothing downstream can tell that it happened.
--
-- The columns mirror the record exactly rather than storing JSON: calibration is
-- segmented by hops, correlated_hops and weight_basis, and a segment you cannot index or
-- query is a segment nobody computes.

CREATE TABLE IF NOT EXISTS validations (
    tenant               text        NOT NULL,
    id                   text        NOT NULL,
    path_id              text        NOT NULL DEFAULT '',
    outcome              text        NOT NULL,
    source               text        NOT NULL DEFAULT '',
    evidence             text        NOT NULL DEFAULT '',
    route                text        NOT NULL DEFAULT '',
    tested_at            timestamptz NOT NULL,
    predicted_score      double precision NOT NULL DEFAULT 0,
    scope                text        NOT NULL DEFAULT '',
    predicted_compromise double precision NOT NULL DEFAULT 0,
    hops                 integer     NOT NULL DEFAULT 0,
    correlated_hops      boolean     NOT NULL DEFAULT false,
    weight_basis         text        NOT NULL DEFAULT '',
    -- NULL means the detection axis was not recorded for this verdict, which is
    -- different from "recorded as not detected" - the first is absent evidence, the
    -- second is evidence of absence, and the diagnostics treat them differently.
    detected             boolean,
    PRIMARY KEY (tenant, id)
);

CREATE INDEX IF NOT EXISTS validations_tenant_tested ON validations (tenant, tested_at DESC);
CREATE INDEX IF NOT EXISTS validations_path ON validations (tenant, path_id);
