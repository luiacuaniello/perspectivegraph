-- Durable brute-force lockouts.
--
-- The lockout was in-memory only, which made it a control an attacker could wait out:
-- a restart, a deploy or an OOM cleared every lockout, and a release schedule is
-- something anyone can read. It was also per-replica - the same client simply retried
-- until it reached a pod that had never heard of it.
--
-- Only the LOCKOUT is stored, not the failure counter behind it. Counting stays in
-- memory on purpose: a row written per failed login would let anyone with a socket
-- drive unbounded writes into the database, turning an anti-abuse control into an
-- amplifier for the abuse. So what a restart still forgives is partial progress toward
-- the threshold; what it no longer forgives is a lockout already earned.
--
-- The key is an opaque string chosen by the caller (a client IP today). Rows are
-- disposable: losing this table costs one window of lockouts, not correctness.

CREATE TABLE IF NOT EXISTS auth_lockout (
    key          text        PRIMARY KEY,
    locked_until timestamptz NOT NULL
);

-- Expiry is swept by time, so that is what the sweep reads.
CREATE INDEX IF NOT EXISTS auth_lockout_until ON auth_lockout (locked_until);
