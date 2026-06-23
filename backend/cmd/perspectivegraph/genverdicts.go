package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/validation"
)

// runGenverdicts is a ground-truth *simulator* for the calibration loop: it lets you
// exercise and TEST the calibration math + diagnostics in development, without real
// vulnerable infrastructure or a BAS platform.
//
//	perspectivegraph genverdicts --scenario overconfident --count 400 --reset
//
// It does NOT fake calibration evidence. It draws verdicts from a *known* reality you
// control (a scenario), so the instrument can be checked against ground truth - exactly
// how you'd integration-test a calibration system. Each scenario should drive a
// specific diagnosis:
//
//	calibrated      reality = the model's own scores      → "calibrated" (the math is right)
//	overconfident   reality harder than predicted (p^2.2) → "recalibrate-first"
//	underconfident  reality easier than predicted (p^0.45)→ "recalibrate-first"
//	correlated      correlated-hop paths over-confirm     → "structural (#6)"
//	low-resolution  outcome independent of the score      → "low-resolution"
//	detection       calibrated, but reachable paths caught → "detection-axis (#7)"
//
// The verdicts are clearly labelled synthetic (source "genverdicts/<scenario>"), and
// this validates the *instrument*, never the engine's scores against the real world -
// that still needs real verdicts.
func runGenverdicts(args []string) error {
	fs := flag.NewFlagSet("genverdicts", flag.ContinueOnError)
	api := fs.String("api", "http://localhost:8080", "API base URL")
	scenario := fs.String("scenario", "calibrated", "calibrated|overconfident|underconfident|correlated|low-resolution|detection")
	count := fs.Int("count", 400, "synthetic verdicts to generate")
	token := fs.String("token", os.Getenv("API_TOKEN"), "bearer token, if API auth is on")
	randSeed := fs.Int64("rand", 7, "PRNG seed (reproducible scenarios)")
	reset := fs.Bool("reset", false, "delete the tenant's existing verdicts first (clean slate)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *count < 1 {
		return fmt.Errorf("count must be >= 1")
	}
	verdicts, ok := validation.GenerateScenario(*scenario, *count, uint64(*randSeed)) // #nosec G115 -- PRNG seed
	if !ok {
		return fmt.Errorf("unknown scenario %q (see --help)", *scenario)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	if *reset {
		n, err := resetVerdicts(client, *api, *token)
		if err != nil {
			return fmt.Errorf("reset: %w", err)
		}
		fmt.Printf("genverdicts: deleted %d existing verdict(s)\n", n)
	}

	posted, confirmed, detectedN := 0, 0, 0
	for i, v := range verdicts {
		body := map[string]any{
			"pathId":         v.PathID,
			"outcome":        string(v.Outcome),
			"source":         "genverdicts/" + *scenario,
			"evidence":       "synthetic self-test verdict (NOT real)",
			"predictedScore": v.PredictedScore,
			"hops":           v.Hops,
			"correlatedHops": v.CorrelatedHops,
		}
		if v.Outcome == validation.Confirmed {
			confirmed++
		}
		if v.Detected != nil {
			body["detected"] = *v.Detected
			if *v.Detected {
				detectedN++
			}
		}
		if err := postVerdict(client, *api, *token, body); err != nil {
			return fmt.Errorf("verdict %d: %w", i, err)
		}
		posted++
	}

	fmt.Printf("genverdicts[%s]: posted %d verdicts (%d confirmed, %d detected) → %s\n",
		*scenario, posted, confirmed, detectedN, *api)
	fmt.Printf("  read the diagnosis: curl -s %s/validations | jq '.calibration | {verdict,brier,brier_recalibrated,diagnosis}'\n", *api)
	return nil
}

// apiRequest performs one API call, backing off and retrying on 429 so a burst of
// verdicts rides through the per-IP rate limiter (it adapts to whatever the limit is,
// no config change needed).
func apiRequest(client *http.Client, method, url, token string, body []byte) (int, []byte, error) {
	for attempt := 0; ; attempt++ {
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(context.Background(), method, url, rdr)
		if err != nil {
			return 0, nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		rb, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests && attempt < 10 {
			shift := attempt
			if shift > 7 {
				shift = 7
			}
			time.Sleep(time.Duration(15<<shift) * time.Millisecond) // 15ms → ~2s, capped
			continue
		}
		return resp.StatusCode, rb, nil
	}
}

func postVerdict(client *http.Client, api, token string, body map[string]any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	st, rb, err := apiRequest(client, http.MethodPost, api+"/validations", token, b)
	if err != nil {
		return err
	}
	if st >= 300 {
		return fmt.Errorf("POST /validations returned %d: %s", st, string(rb))
	}
	return nil
}

// resetVerdicts deletes all of the tenant's current verdicts, for a clean scenario run.
func resetVerdicts(client *http.Client, api, token string) (int, error) {
	st, rb, err := apiRequest(client, http.MethodGet, api+"/validations", token, nil)
	if err != nil {
		return 0, err
	}
	if st >= 300 {
		return 0, fmt.Errorf("GET /validations returned %d", st)
	}
	var list struct {
		Validations []struct {
			ID string `json:"id"`
		} `json:"validations"`
	}
	if err := json.Unmarshal(rb, &list); err != nil {
		return 0, err
	}
	n := 0
	for _, v := range list.Validations {
		if v.ID == "" {
			continue
		}
		dst, _, err := apiRequest(client, http.MethodDelete, api+"/validations/"+v.ID, token, nil)
		if err != nil {
			return n, err
		}
		if dst < 300 {
			n++
		}
	}
	return n, nil
}
