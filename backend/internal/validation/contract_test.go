package validation

// Both backends must satisfy the same contract.
var (
	_ Verdicts = (*Store)(nil)
	_ Verdicts = (*PGStore)(nil)
)
