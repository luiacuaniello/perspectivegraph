package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// runIngestReal is the zero-cost "real ingest" helper: it scans a genuinely
// vulnerable image with Trivy (real CVEs, real CVSS; real KEV/EPSS with
// THREATINTEL=on) and wires the minimal topology so a full attack path forms with
// the real CVE *on* it - the on-ramp to calibrating on real data:
//
//	# with a vulhub log4shell env running, or any log4j-vulnerable image:
//	perspectivegraph ingestreal --image <the-vulnerable-image>
//
// Trivy emits Image --DEPENDS_ON--> Library --AFFECTS--> CVE. This adds an
// internet-exposed load balancer that EXPOSES the image, and marks a Secret as a
// sensitive asset that the chosen CVE EXPLOITS - so the analyzer surfaces
// internet-lb → image → library → CVE(log4shell) → sensitive-asset, scored on the CVE's
// *real* severity/KEV/EPSS. The vulnerability evidence is real; the surrounding
// deployment topology you model here (or use the k8s collector for real topology).
// Then exploit the target for real and record the verdict with `importverdicts`.
func runIngestReal(args []string) error {
	fs := flag.NewFlagSet("ingestreal", flag.ContinueOnError)
	image := fs.String("image", "", "vulnerable image to scan with Trivy (e.g. the running vulhub log4shell image)")
	ingest := fs.String("ingest", "http://localhost:8081", "ingest base URL")
	token := fs.String("token", os.Getenv("API_TOKEN"), "bearer token if ingest auth is on (HMAC-secured ingest is not handled here)")
	cveWant := fs.String("cve", "CVE-2021-44228", "CVE to place on the attack path (must be present in the scan)")
	jewel := fs.String("jewel", "secrets-vault (sensitive asset)", "sensitive-asset node name")
	entry := fs.String("entry", "internet-lb (log4shell demo)", "internet-exposed entry node name")
	reportFile := fs.String("report", "", "use this Trivy JSON report instead of running trivy (offline / no trivy binary)")
	trivyBin := fs.String("trivy", "trivy", "path to the trivy binary")
	if err := fs.Parse(args); err != nil {
		return err
	}

	reportBytes, err := trivyReport(*reportFile, *trivyBin, *image)
	if err != nil {
		return err
	}

	// Parse just enough to find the image name and the CVE to place on the path.
	var rep struct {
		ArtifactName string `json:"ArtifactName"`
		Results      []struct {
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				Severity        string `json:"Severity"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(reportBytes, &rep); err != nil {
		return fmt.Errorf("parse trivy report: %w", err)
	}
	if rep.ArtifactName == "" {
		return fmt.Errorf("trivy report has no ArtifactName (not an image report?)")
	}
	cves := map[string]bool{}
	var first string
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			if v.VulnerabilityID == "" {
				continue
			}
			if first == "" {
				first = v.VulnerabilityID
			}
			cves[v.VulnerabilityID] = true
		}
	}
	if len(cves) == 0 {
		return fmt.Errorf("trivy found no vulnerabilities in %q - nothing to build a path on", rep.ArtifactName)
	}
	target := *cveWant
	if !cves[target] {
		fmt.Printf("  ! %s not found in the scan; using %s instead (pass --cve to pick another)\n", *cveWant, first)
		target = first
	}

	client := &http.Client{Timeout: 60 * time.Second}
	// 1. Real vulnerability evidence: the native Trivy report.
	if st, rb, err := apiRequest(client, http.MethodPost, *ingest+"/ingest/trivy", *token, reportBytes); err != nil {
		return fmt.Errorf("POST /ingest/trivy: %w", err)
	} else if st >= 300 {
		return fmt.Errorf("POST /ingest/trivy returned %d: %s", st, string(rb))
	}

	// 2. Minimal modeled topology so the CVE sits on an internet → sensitive-asset path.
	imageID := ontology.NewID(ontology.LabelImage, rep.ArtifactName)
	cveID := ontology.NewID(ontology.LabelCVE, target)
	lbID := ontology.NewID(ontology.LabelLoadBalancer, *entry)
	jewelID := ontology.NewID(ontology.LabelSecret, *jewel)
	ev := ontology.Event{
		Source:     "ingestreal",
		Kind:       ontology.KindAsset,
		ObservedAt: time.Now().UTC(),
		Nodes: []ontology.Node{
			{ID: lbID, Label: ontology.LabelLoadBalancer, Name: *entry, Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: jewelID, Label: ontology.LabelSecret, Name: *jewel, Properties: map[string]any{
				ontology.PropCrownJewel: true, ontology.PropCrownJewelBasis: "tagged:operator",
			}},
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeExposes, From: lbID, To: imageID, ExploitProbability: 0.9},
			{Type: ontology.EdgeExploits, From: cveID, To: jewelID, ExploitProbability: 0.9},
		},
	}
	body, err := json.Marshal([]ontology.Event{ev})
	if err != nil {
		return err
	}
	if st, rb, err := apiRequest(client, http.MethodPost, *ingest+"/ingest/events", *token, body); err != nil {
		return fmt.Errorf("POST /ingest/events: %w", err)
	} else if st >= 300 {
		return fmt.Errorf("POST /ingest/events returned %d: %s", st, string(rb))
	}

	fmt.Printf("ingestreal: ingested %s (%d CVEs) + topology → path %s → %s → %s\n",
		rep.ArtifactName, len(cves), *entry, target, *jewel)
	fmt.Printf("  give the analyzer a pass, then: curl -s -XPOST localhost:8080/graphql -d '{\"query\":\"{ attackPaths { id score nodes { name } } }\"}'\n")
	fmt.Printf("  then exploit the target for real and record the verdict:\n")
	fmt.Printf("    importverdicts with {\"target\":%q,\"from\":%q,\"outcome\":\"confirmed\"}\n", *jewel, *entry)
	return nil
}

// trivyReport returns the Trivy JSON, from a file (offline) or by running trivy.
func trivyReport(reportFile, trivyBin, image string) ([]byte, error) {
	if reportFile != "" {
		return os.ReadFile(reportFile) // #nosec G304 -- operator-supplied report path
	}
	if image == "" {
		return nil, fmt.Errorf("need --image (to scan) or --report (a Trivy JSON file)")
	}
	cmd := exec.Command(trivyBin, "image", "-q", "-f", "json", "--scanners", "vuln", image) // #nosec G204 -- operator-supplied image/binary
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		hint := ""
		if strings.Contains(err.Error(), "executable file not found") {
			hint = " (is Trivy installed? https://trivy.dev)"
		}
		return nil, fmt.Errorf("run %s image %s: %w%s: %s", trivyBin, image, err, hint, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
