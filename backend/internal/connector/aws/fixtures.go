package aws

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// fixturesTransport reads describe-* JSON from a local directory — the path that
// proves the whole pull pipeline without real AWS credentials. The fixtures are
// the very same shapes the cloudnet/iam collectors consume (and the very same
// files used for `make seed-discovery`), so "demo on fixtures" and "live on AWS"
// exercise identical downstream code.
type fixturesTransport struct {
	dir   string
	files map[Feed]string
}

// Fixtures returns a transport that serves each feed from <dir>/<file>. A missing
// file means that feed is simply absent (nil, nil), not an error — so a dir with
// only the network sample still works.
func Fixtures(dir string) transport {
	return &fixturesTransport{
		dir: dir,
		files: map[Feed]string{
			FeedNetwork: "cloudnet-sample.json",
			FeedIAM:     "iam-sample.json",
		},
	}
}

func (f *fixturesTransport) Mode() string { return "fixtures" }

func (f *fixturesTransport) Fetch(_ context.Context, feed Feed) ([]byte, error) {
	name, ok := f.files[feed]
	if !ok {
		return nil, nil
	}
	b, err := os.ReadFile(filepath.Join(f.dir, name)) // #nosec G304 -- operator-configured fixtures dir, fixed filenames
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // feed not present in this fixtures dir
	}
	return b, err
}
