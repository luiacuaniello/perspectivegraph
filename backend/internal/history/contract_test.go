package history

// Both backends must satisfy the same contract.
var (
	_ Temporal = (*Store)(nil)
	_ Temporal = (*PGStore)(nil)
)
