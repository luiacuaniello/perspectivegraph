package kevholdout

// Both backends must satisfy the same contract.
var (
	_ Holdout = (*Store)(nil)
	_ Holdout = (*PGStore)(nil)
)
