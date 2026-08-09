package ticket

// Both backends must satisfy the same contract, or picking one would silently lose a
// method the other has.
var (
	_ Tickets = (*Store)(nil)
	_ Tickets = (*PGStore)(nil)
)
