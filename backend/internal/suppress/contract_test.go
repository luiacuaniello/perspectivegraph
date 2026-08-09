package suppress

// Both backends must satisfy the same contract, or a deployment could pick one and lose
// a method the other has.
var (
	_ Suppressions = (*Store)(nil)
	_ Suppressions = (*PGStore)(nil)
)
