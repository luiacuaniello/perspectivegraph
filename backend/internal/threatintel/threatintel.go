// Package threatintel enriches CVE nodes with real-world exploitation signal so
// edge weights reflect what attackers actually do, not just severity labels:
//
//   - CISA KEV (Known Exploited Vulnerabilities) - a binary "exploited in the
//     wild" flag. A KEV CVE on a reachable path is confirmed, not theoretical.
//   - FIRST EPSS (Exploit Prediction Scoring System) - the probability a CVE
//     will be exploited in the next 30 days, [0,1].
//
// It is optional (like the search index): with it disabled the Noop source is
// used and the AFFECTS edge keeps its severity-derived probability.
package threatintel

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/httpx"
)

const (
	defaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	defaultEPSSURL = "https://api.first.org/data/v1/epss"
	epssBatchSize  = 100
)

// Intel is the per-CVE enrichment.
type Intel struct {
	EPSS       float64 // P(exploitation within 30 days), [0,1]
	Percentile float64 // EPSS percentile rank, [0,1]
	KEV        bool    // present in CISA's Known Exploited Vulnerabilities catalog
}

// EdgeProbability upgrades a severity-derived fallback with observed intel:
// a KEV CVE is exploited in the wild, so it floors high; otherwise EPSS is the
// better estimate when known; otherwise the severity fallback stands.
func (i Intel) EdgeProbability(fallback float64) float64 {
	switch {
	case i.KEV:
		if i.EPSS > 0.95 {
			return i.EPSS
		}
		return 0.95
	case i.EPSS > 0:
		return i.EPSS
	default:
		return fallback
	}
}

// Basis names the strongest evidence behind the probability EdgeProbability
// returns: "kev" (exploited in the wild) beats "epss" (data-driven prediction);
// "" when neither applies and the severity fallback stands.
func (i Intel) Basis() string {
	switch {
	case i.KEV:
		return "kev"
	case i.EPSS > 0:
		return "epss"
	default:
		return ""
	}
}

// Source returns intel for a set of CVE ids.
type Source interface {
	Enabled() bool
	// Scores returns intel for the requested CVEs; CVEs with neither KEV nor
	// EPSS data are omitted. Network failures degrade gracefully to cache.
	Scores(ctx context.Context, cves []string) map[string]Intel
}

// Noop is the disabled source.
type Noop struct{}

func (Noop) Enabled() bool                                     { return false }
func (Noop) Scores(context.Context, []string) map[string]Intel { return nil }

// New returns a live KEV+EPSS source, or Noop when disabled. Empty URLs use the
// official feeds.
func New(enabled bool, kevURL, epssURL string) Source {
	if !enabled {
		return Noop{}
	}
	if kevURL == "" {
		kevURL = defaultKEVURL
	}
	if epssURL == "" {
		epssURL = defaultEPSSURL
	}
	return &Live{
		kevURL:  kevURL,
		epssURL: epssURL,
		client:  &http.Client{Timeout: 12 * time.Second},
		ttl:     6 * time.Hour,
		kev:     map[string]bool{},
		epss:    map[string]Intel{},
		epssAt:  map[string]time.Time{},
	}
}

// Live fetches from CISA KEV and FIRST EPSS, caching results with a TTL.
type Live struct {
	kevURL, epssURL string
	client          *http.Client
	ttl             time.Duration

	mu     sync.Mutex
	kev    map[string]bool
	kevAt  time.Time
	epss   map[string]Intel
	epssAt map[string]time.Time // last fetch attempt per CVE (incl. misses)
}

func (l *Live) Enabled() bool { return true }

func (l *Live) Scores(ctx context.Context, cves []string) map[string]Intel {
	if len(cves) == 0 {
		return nil
	}
	l.ensureKEV(ctx)
	l.ensureEPSS(ctx, cves)

	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]Intel{}
	for _, cve := range cves {
		in := Intel{KEV: l.kev[cve]}
		if e, ok := l.epss[cve]; ok {
			in.EPSS, in.Percentile = e.EPSS, e.Percentile
		}
		if in.KEV || in.EPSS > 0 {
			out[cve] = in
		}
	}
	return out
}

func (l *Live) ensureKEV(ctx context.Context) {
	l.mu.Lock()
	fresh := len(l.kev) > 0 && time.Since(l.kevAt) < l.ttl
	l.mu.Unlock()
	if fresh {
		return
	}
	var resp struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := httpx.Do(ctx, l.client, http.MethodGet, l.kevURL, nil, "", nil, &resp); err != nil {
		slog.Warn("threatintel: KEV fetch failed (using cache)", "err", err)
		return
	}
	set := make(map[string]bool, len(resp.Vulnerabilities))
	for _, v := range resp.Vulnerabilities {
		set[v.CveID] = true
	}
	l.mu.Lock()
	l.kev, l.kevAt = set, time.Now()
	l.mu.Unlock()
}

func (l *Live) ensureEPSS(ctx context.Context, cves []string) {
	l.mu.Lock()
	var need []string
	for _, c := range cves {
		if at, ok := l.epssAt[c]; !ok || time.Since(at) >= l.ttl {
			need = append(need, c)
		}
	}
	l.mu.Unlock()
	if len(need) == 0 {
		return
	}

	got := map[string]Intel{}
	for _, chunk := range chunk(need, epssBatchSize) {
		m, err := fetchEPSS(ctx, l.client, l.epssURL, chunk)
		if err != nil {
			slog.Warn("threatintel: EPSS fetch failed", "err", err)
			continue
		}
		for k, v := range m {
			got[k] = v
		}
	}

	now := time.Now()
	l.mu.Lock()
	for _, c := range need {
		if v, ok := got[c]; ok {
			l.epss[c] = v
		}
		l.epssAt[c] = now // mark attempted so we don't refetch misses every event
	}
	l.mu.Unlock()
}

func fetchEPSS(ctx context.Context, client *http.Client, base string, cves []string) (map[string]Intel, error) {
	url := base + "?cve=" + strings.Join(cves, ",")
	var resp struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
		} `json:"data"`
	}
	if err := httpx.Do(ctx, client, http.MethodGet, url, nil, "", nil, &resp); err != nil {
		return nil, err
	}
	out := make(map[string]Intel, len(resp.Data))
	for _, d := range resp.Data {
		epss, _ := strconv.ParseFloat(d.EPSS, 64)
		pct, _ := strconv.ParseFloat(d.Percentile, 64)
		out[d.CVE] = Intel{EPSS: epss, Percentile: pct}
	}
	return out, nil
}

func chunk(s []string, n int) [][]string {
	var out [][]string
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}
