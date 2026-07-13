// Package fuzz fuzzes the collector parse boundary - the one place PerspectiveGraph
// turns attacker-influenceable input (scanner reports, cloud/cluster dumps) into
// ontology events. Every collector shares the same Parse surface, so one package
// fuzzes them all. The goal is robustness: Parse must never panic, hang, or OOM on
// malformed input; returning an error is the correct behaviour for junk.
//
// Seeds run on every `go test` (cheap regression). Deep fuzzing is opt-in:
//
//	cd backend && go test ./internal/ingestion/fuzz -run x -fuzz FuzzCloudnet -fuzztime 60s
//
// or via `make fuzz`. The same targets are OSS-Fuzz-compatible.
package fuzz

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/build"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/cloudnet"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/custodian"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/dataclass"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/falco"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/iam"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/k8s"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/semgrep"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/sso"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/supplychain"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/trivy"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// parser is the untrusted-input boundary every collector shares.
type parser interface {
	Parse(io.Reader, ingestion.Options) ([]ontology.Event, error)
}

// run seeds the corpus (empty, "{}", and a real sample) and asserts Parse never panics.
func run(f *testing.F, p parser, sample string) {
	f.Helper()
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	if b, err := os.ReadFile(sample); err == nil { // #nosec G304 -- fixed testdata path
		f.Add(b)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = p.Parse(bytes.NewReader(data), ingestion.Options{})
	})
}

func FuzzCloudnet(f *testing.F)  { run(f, cloudnet.New(), "../../../testdata/cloudnet-sample.json") }
func FuzzIAM(f *testing.F)       { run(f, iam.New(), "../../../testdata/iam-sample.json") }
func FuzzK8s(f *testing.F)       { run(f, k8s.New(), "../../../testdata/k8s-sample.json") }
func FuzzTrivy(f *testing.F)     { run(f, trivy.New(), "../../../testdata/trivy-sample.json") }
func FuzzSemgrep(f *testing.F)   { run(f, semgrep.New(), "../../../testdata/semgrep-sample.json") }
func FuzzFalco(f *testing.F)     { run(f, falco.New(), "../../../testdata/falco-sample.json") }
func FuzzCustodian(f *testing.F) { run(f, custodian.New(), "../../../testdata/custodian-sample.json") }
func FuzzSupplychain(f *testing.F) {
	run(f, supplychain.New(), "../../../testdata/supplychain-sample.json")
}
func FuzzSSO(f *testing.F)       { run(f, sso.New(), "../../../testdata/sso-sample.json") }
func FuzzDataclass(f *testing.F) { run(f, dataclass.New(), "../../../testdata/dataclass-sample.json") }
func FuzzBuild(f *testing.F)     { run(f, build.New(), "../../../testdata/build-sample.json") }
