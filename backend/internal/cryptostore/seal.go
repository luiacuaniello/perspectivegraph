package cryptostore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/luiacuaniello/perspectivegraph/internal/atomicfile"
)

// Report is what sealing one store found.
type Report struct {
	// Absent: there was nothing to seal - no file, or an empty one.
	Absent bool
	// Sealed counts the records the key had already sealed, and Plain the records in
	// plaintext: sealed now, or in a dry run, the ones that would be. A store kept as one
	// blob counts as one record.
	Sealed, Plain int
	// Torn counts a final record cut short by a crash, which the store drops when it
	// loads, and which sealing drops too rather than carry forward.
	Torn int
}

// SealFile seals a store kept as one blob: the suppressions, the tickets, the history and
// the validation store's first format. A sealed blob has to open with s, which proves s
// is the key that sealed it; a plaintext one has to be JSON, so that a file that is
// neither is reported rather than wrapped. Unless dryRun, a plaintext blob is replaced by
// its sealed form, atomically and readable by the owner alone.
func SealFile(path string, s Sealer, dryRun bool) (Report, error) {
	if !s.Enabled() {
		return Report{}, errors.New("cryptostore: no key to seal with")
	}
	b, err := os.ReadFile(path) // #nosec G304 -- operator-configured store path, not attacker-controlled
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(b) == 0) {
		return Report{Absent: true}, nil
	}
	if err != nil {
		return Report{}, err
	}
	if IsSealed(b) {
		if _, err := s.Open(b); err != nil {
			return Report{}, fmt.Errorf("%s is sealed, but not with this key: %w", path, err)
		}
		return Report{Sealed: 1}, nil
	}
	if !json.Valid(b) {
		return Report{}, fmt.Errorf("%s is neither sealed nor JSON: not a store this engine wrote, or corrupt", path)
	}
	if dryRun {
		return Report{Plain: 1}, nil
	}
	sealed, err := s.Seal(b)
	if err != nil {
		return Report{}, err
	}
	if err := atomicfile.Write(path, sealed, 0o600); err != nil {
		return Report{}, err
	}
	return Report{Plain: 1}, nil
}
