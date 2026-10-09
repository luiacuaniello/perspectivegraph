package kubernetes

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// fixturesTransport serves a dump from disk - k8s-sample.json, the shape `kubectl get … -A
// -o json` writes - so the pull runs end to end without a cluster. A dump on disk is the
// whole of what it describes, so it reads as complete.
type fixturesTransport struct{ dir string }

// Fixtures returns a transport that serves <dir>/k8s-sample.json. A missing file is no
// cluster, not an error.
func Fixtures(dir string) transport { return &fixturesTransport{dir: dir} }

func (f *fixturesTransport) Mode() string { return "fixtures" }

func (f *fixturesTransport) Fetch(context.Context) ([]byte, bool, error) {
	b, err := os.ReadFile(filepath.Join(f.dir, "k8s-sample.json")) // #nosec G304 -- operator-configured fixtures dir, fixed filename
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}
