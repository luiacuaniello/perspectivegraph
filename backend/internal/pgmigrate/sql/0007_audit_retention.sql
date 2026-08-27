-- Retention for the tamper-evident audit log.
--
-- An append-only chain that nobody may delete from grows forever, and "forever" is not a
-- retention policy - it is the absence of one, and the thing a data-protection review
-- raises first. But deleting a record from the middle of a hash chain breaks every link
-- after it, and a verifier that cannot tell that from tampering is worthless. Erasure and
-- tamper-evidence pull in opposite directions.
--
-- The way out is to delete only from the FRONT, and to leave a signed-off note saying so.
-- This table is that note: it records how far the log was pruned, and the hash of the last
-- record removed. Verification then starts at the first surviving record and checks it
-- links to that hash - so the retained window is exactly as tamper-evident as the whole
-- chain was, while records older than the window are gone.
--
-- What this deliberately does NOT allow is deleting one record out of the middle. That
-- would be the "surgery" the threat model rules out: it is indistinguishable from an
-- attacker removing their own entry, which is the one thing the chain exists to expose.

CREATE TABLE IF NOT EXISTS audit_log_checkpoint (
    -- Single row: the checkpoint is a property of the log, not a list of events. The
    -- CHECK makes a second row impossible rather than merely unexpected.
    id                  boolean     PRIMARY KEY DEFAULT true CHECK (id),
    -- Records with seq <= this were removed on purpose; the chain resumes at seq + 1.
    pruned_through_seq  bigint      NOT NULL,
    -- The hash of record `pruned_through_seq`, which the first surviving record's
    -- prev_hash must still match. This is what keeps the truncated chain verifiable.
    pruned_through_hash text        NOT NULL,
    -- Lifetime total, for the operator who wants to know what retention has cost them.
    pruned_records      bigint      NOT NULL DEFAULT 0,
    pruned_at           timestamptz NOT NULL
);

-- Retention prunes by age, so the scan that finds the cutoff should not be a seq-ordered
-- table scan.
CREATE INDEX IF NOT EXISTS audit_log_at ON audit_log (at);
