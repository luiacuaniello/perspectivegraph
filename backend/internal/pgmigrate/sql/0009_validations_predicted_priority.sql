-- The triage Priority a path had when a verdict was recorded.
--
-- Calibration grades whether the engine's numbers are honest, and precision/recall grade
-- whether its paths are real. Neither grades the ORDER - the Priority an operator sorts by
-- and works down - so capturing it at verdict time is what lets discrimination measure the
-- ranking people actually use rather than only S(P).
--
-- Nullable, and deliberately not NOT NULL DEFAULT 0 like predicted_score. Priority is
-- rounded to one decimal, so a weak path legitimately scores 0.0; a zero default would make
-- "captured as the lowest priority" and "never captured" the same row, and the calibration
-- would have to drop both - which removes exactly the refuted, low-priority verdicts the
-- metric depends on and flatters it. NULL is "not captured": every verdict recorded before
-- this migration, and any whose path was no longer live.

ALTER TABLE validations ADD COLUMN IF NOT EXISTS predicted_priority double precision;
