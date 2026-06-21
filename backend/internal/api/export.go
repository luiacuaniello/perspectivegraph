package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/compliance"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// signExport stamps the detached-signature headers on an export response when an
// export signer is configured. Must be called before the body is written.
func (a *API) signExport(w http.ResponseWriter, body []byte) {
	if a.exportSigner.Enabled() {
		w.Header().Set("X-PerspectiveGraph-Signature", a.exportSigner.Sign(body))
		w.Header().Set("X-PerspectiveGraph-PublicKey", a.exportSigner.PublicKeyB64())
	}
}

// exportPubKey serves the Ed25519 public key consumers use to verify a signed
// export. Open (the key is public); 404 when export signing is disabled.
func (a *API) exportPubKey(w http.ResponseWriter, _ *http.Request) {
	if !a.exportSigner.Enabled() {
		http.Error(w, "export signing is not enabled", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"algorithm":  "ed25519",
		"public_key": a.exportSigner.PublicKeyB64(),
	})
}

// enrichment is one SIEM enrichment record: an asset that sits on a critical
// attack path, with the risk context a SIEM uses to prioritize alerts about it
// ("this host is on 3 critical paths, KEV present"). The shape is flat on
// purpose so Splunk/Elastic/Sentinel can index and correlate it directly.
type enrichment struct {
	Schema           string   `json:"@schema"`
	Tenant           string   `json:"tenant"`
	AssetID          string   `json:"asset_id"`
	AssetName        string   `json:"asset_name"`
	Label            string   `json:"label"`
	OnCriticalPath   bool     `json:"on_critical_path"`
	PathCount        int      `json:"path_count"`
	MaxPathScore     float64  `json:"max_path_score"`
	RuntimeConfirmed bool     `json:"runtime_confirmed"`
	KEV              bool     `json:"kev"`
	InternetExposed  bool     `json:"internet_exposed"`
	CrownJewel       bool     `json:"crown_jewel"`
	PathIDs          []string `json:"path_ids"`
}

// exportNDJSON streams one enrichment record per asset on a critical path, as
// newline-delimited JSON — the format Splunk HEC / Elastic / Sentinel ingest.
// Scoped to the caller's tenant; auth-gated like the GraphQL endpoint.
func (a *API) exportNDJSON(w http.ResponseWriter, r *http.Request) {
	tenant := tenantOf(r.Context())
	paths := a.scopedLatest(r.Context())
	records := buildEnrichment(tenant, paths)

	// Exporting streams the whole attack map out of the tool — audit who did it.
	a.auditView(r.Context(), "export.ndjson", map[string]any{"assets": len(records), "paths": len(paths)})

	// Buffer so the body can be signed (the signature header must precede it).
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			http.Error(w, "encode export", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	a.signExport(w, buf.Bytes())
	_, _ = w.Write(buf.Bytes())
}

// exportOSCAL returns the tenant's attack-path posture as a NIST OSCAL 1.1.2
// assessment-results document — the artifact GRC tooling and auditors consume.
// Same tenant scoping + auth as the GraphQL endpoint.
func (a *API) exportOSCAL(w http.ResponseWriter, r *http.Request) {
	tenant := tenantOf(r.Context())
	paths := a.scopedLatest(r.Context())
	doc := compliance.Build(tenant, paths, time.Now().UTC())

	a.auditView(r.Context(), "export.oscal", map[string]any{"paths": len(paths)})

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		http.Error(w, "encode export", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="perspectivegraph-oscal.json"`)
	a.signExport(w, body)
	_, _ = w.Write(body)
}

func buildEnrichment(tenant string, paths []analyzer.AttackPath) []enrichment {
	byID := map[string]*enrichment{}
	for _, p := range paths {
		for _, n := range p.Nodes {
			rec := byID[n.ID]
			if rec == nil {
				rec = &enrichment{
					Schema: "perspectivegraph.enrichment.v1", Tenant: tenant,
					AssetID: n.ID, AssetName: n.Name, Label: string(n.Label),
					OnCriticalPath:  true,
					InternetExposed: n.Bool(ontology.PropInternetExposed),
					CrownJewel:      n.Bool(ontology.PropCrownJewel),
				}
				byID[n.ID] = rec
			}
			rec.PathCount++
			rec.PathIDs = append(rec.PathIDs, p.ID)
			if p.Score > rec.MaxPathScore {
				rec.MaxPathScore = p.Score
			}
			if p.RuntimeConfirmed {
				rec.RuntimeConfirmed = true
			}
			if n.Label == ontology.LabelCVE && n.Bool(ontology.PropKEV) {
				rec.KEV = true
			}
		}
	}

	out := make([]enrichment, 0, len(byID))
	for _, rec := range byID {
		out = append(out, *rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].MaxPathScore != out[j].MaxPathScore {
			return out[i].MaxPathScore > out[j].MaxPathScore
		}
		return out[i].AssetID < out[j].AssetID
	})
	return out
}
