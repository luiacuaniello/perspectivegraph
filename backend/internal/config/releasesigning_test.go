package config

import (
	"regexp"
	"strings"
	"testing"
)

// The release binaries were signed and attested from the start, and OpenSSF Scorecard still
// scored every release 0 for Signed-Releases: it reads release ASSETS, by extension, and the
// signature was attached as .bundle while the provenance lived only in GitHub's attestation
// API. The names are the contract, so this holds them - along with the older name the GitHub
// Action still downloads, and the order that makes a published file a verified one.
func TestReleaseBinariesPublishSignaturesScorecardRecognises(t *testing.T) {
	root := repoRoot(t)
	workflow := mustRead(t, root, ".github", "workflows", "publish-images.yml")
	start := strings.Index(workflow, "\n  binaries:\n")
	end := strings.Index(workflow, "\n  chart:\n")
	if start < 0 || end < start {
		t.Fatal("publish-images.yml has no binaries job followed by the chart job")
	}
	job := workflow[start:end]

	// Scorecard's Signed-Releases check: *.sigstore.json (and friends) for a signature,
	// *.intoto.jsonl for provenance, which is what earns the full score.
	for _, published := range []string{"dist/SHA256SUMS.sigstore.json", "dist/perspectivegraph.intoto.jsonl"} {
		if !strings.Contains(job, published) {
			t.Errorf("the binaries job does not produce %s", published)
		}
	}

	upload := strings.Index(job, "gh release upload")
	if upload < 0 {
		t.Fatal("the binaries job never uploads to the release")
	}
	for name, verify := range map[string]*regexp.Regexp{
		"the checksum signature": regexp.MustCompile(`cosign verify-blob \\\s+--bundle dist/SHA256SUMS\.sigstore\.json`),
		"the provenance":         regexp.MustCompile(`cosign verify-blob-attestation \\\s+--bundle dist/perspectivegraph\.intoto\.jsonl`),
	} {
		loc := verify.FindStringIndex(job)
		if loc == nil {
			t.Errorf("%s is published but never verified in the job", name)
			continue
		}
		if loc[0] > upload {
			t.Errorf("%s is verified after the upload - a file that fails would already be on the release", name)
		}
	}

	// The Action fetches SHA256SUMS.bundle from whichever release it is pointed at, including
	// every release made before the Scorecard names existed. Dropping the old name would
	// break it for new releases without anyone noticing on this side.
	if !strings.Contains(mustRead(t, root, "action.yml"), "SHA256SUMS.bundle") {
		t.Fatal("action.yml no longer downloads SHA256SUMS.bundle - update this test with it")
	}
	if !strings.Contains(job, "--bundle dist/SHA256SUMS.bundle") || !strings.Contains(job, "cp dist/SHA256SUMS.bundle dist/SHA256SUMS.sigstore.json") {
		t.Error("the binaries job must keep publishing SHA256SUMS.bundle, as the same file as SHA256SUMS.sigstore.json")
	}

	// What users are told to run must name files that exist.
	readme := mustRead(t, root, "README.md")
	for _, name := range []string{"SHA256SUMS.sigstore.json", "perspectivegraph.intoto.jsonl"} {
		if !strings.Contains(readme, "--bundle "+name) {
			t.Errorf("README does not show how to verify with %s", name)
		}
	}
}
