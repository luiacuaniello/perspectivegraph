package validation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/luiacuaniello/perspectivegraph/internal/atomicfile"
	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
)

// SealFile seals a validation store written before STORE_ENCRYPTION_KEY was set. The
// append-only log is sealed line by line, its header kept as it is - plaintext by design,
// so the format is recognised without a key - and the original single-blob format is
// sealed whole. A line the key already sealed has to open with it. Unless dryRun, the
// file is rewritten atomically, owner-only.
//
// A final line torn by a crash is what replay drops, and it is handled by what it was.
// One that was being sealed is kept as it is: a sealed line that does not open could as
// well be one this key never wrote, and nothing here is in a position to destroy it.
// One that was plaintext, or cut inside the sealed prefix, is dropped - kept, it would
// be the plaintext record the key refuses, and the store would not load.
func SealFile(path string, s cryptostore.Sealer, dryRun bool) (cryptostore.Report, error) {
	if !s.Enabled() {
		return cryptostore.Report{}, errors.New("validation: no key to seal with")
	}
	b, err := os.ReadFile(path) // #nosec G304 -- operator-configured store path, not attacker-controlled
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(b) == 0) {
		return cryptostore.Report{Absent: true}, nil
	}
	if err != nil {
		return cryptostore.Report{}, err
	}
	if !bytes.HasPrefix(b, []byte(logMagicV2)) {
		return cryptostore.SealFile(path, s, dryRun)
	}

	lines := bytes.Split(b, []byte("\n"))[1:]
	last := -1
	for i, ln := range lines {
		if len(bytes.TrimSpace(ln)) > 0 {
			last = i
		}
	}
	var (
		rep     cryptostore.Report
		out     bytes.Buffer
		dropped bool
	)
	out.WriteString(logMagicV2)
	out.WriteByte('\n')
	for i, ln := range lines {
		ln = bytes.TrimSpace(ln)
		if len(ln) == 0 {
			continue
		}
		raw, derr := base64.StdEncoding.AppendDecode(nil, ln)
		switch {
		case derr == nil && cryptostore.IsSealed(raw):
			if _, err := s.Open(raw); err != nil {
				if i != last {
					return rep, fmt.Errorf("%s line %d is sealed, but does not open with this key: %w", path, i+2, err)
				}
				rep.Torn++ // kept: see above
			} else {
				rep.Sealed++
			}
			out.Write(ln)
		case derr == nil && json.Valid(raw):
			rep.Plain++
			sealed, err := s.Seal(raw)
			if err != nil {
				return rep, err
			}
			out.WriteString(base64.StdEncoding.EncodeToString(sealed))
		case i == last:
			rep.Torn++
			dropped = true
			continue
		default:
			return rep, fmt.Errorf("%s line %d is neither sealed nor a record: corrupt", path, i+2)
		}
		out.WriteByte('\n')
	}
	if dryRun || (rep.Plain == 0 && !dropped) {
		return rep, nil
	}
	return rep, atomicfile.Write(path, out.Bytes(), 0o600)
}
