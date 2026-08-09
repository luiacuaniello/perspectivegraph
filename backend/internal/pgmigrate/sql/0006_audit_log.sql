-- The tamper-evident audit log.
--
-- This is the last store to move, and the one that could not be ported by repeating the
-- same pattern. Each record carries the hash of the one before it, so the chain is only
-- evidence if every append reads a predecessor NOBODY ELSE is also appending to. With
-- two replicas racing, both read the same tail, both write a record claiming it as
-- prev_hash, and the chain forks: Verify then reports tampering on a log nobody touched,
-- which is worse than no audit log at all - it burns the operator's trust in the one
-- control that is supposed to be trustworthy.
--
-- So an append serialises on a transaction-scoped advisory lock (see audit.PGLog). That
-- is a real cost - appends cannot proceed in parallel - and it is affordable because
-- audit records are authentication denials and mutations, not request traffic.
--
-- seq is assigned inside that same transaction rather than by a sequence: a Postgres
-- sequence does not roll back, so a failed append would leave a gap, and a gap in a
-- chain is indistinguishable from a deletion.

CREATE TABLE IF NOT EXISTS audit_log (
    seq       bigint      PRIMARY KEY,
    at        timestamptz NOT NULL,
    action    text        NOT NULL,
    subject   text        NOT NULL DEFAULT '',
    role      text        NOT NULL DEFAULT '',
    tenant    text        NOT NULL DEFAULT '',
    fields    jsonb,
    prev_hash text        NOT NULL,
    hash      text        NOT NULL
);

-- Verification walks the chain in order; an operator filtering by tenant or action reads
-- the same index.
CREATE INDEX IF NOT EXISTS audit_log_tenant_seq ON audit_log (tenant, seq);
