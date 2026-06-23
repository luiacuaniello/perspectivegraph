// Package notify pushes drift alerts - "a new attack path appeared" - to a
// chat/SOAR webhook, turning the analyzer's passes into something a team sees in
// its daily workflow. It is optional: with no webhook configured the Noop
// notifier is used and drift is only logged.
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/httpx"
)

// PathSummary is the human-readable digest of one attack path.
type PathSummary struct {
	ID               string  `json:"id"`
	Route            string  `json:"route"` // "a → b → c"
	Score            float64 `json:"score"`
	RuntimeConfirmed bool    `json:"runtime_confirmed"`
	KEV              bool    `json:"kev"`
}

// DriftEvent is the change in critical paths between two analysis passes.
type DriftEvent struct {
	Tenant   string        `json:"tenant"`
	Appeared []PathSummary `json:"appeared"`
	Resolved []PathSummary `json:"resolved"`
}

// Empty reports whether nothing changed.
func (d DriftEvent) Empty() bool { return len(d.Appeared) == 0 && len(d.Resolved) == 0 }

// Notifier delivers drift events.
type Notifier interface {
	Enabled() bool
	Notify(ctx context.Context, ev DriftEvent) error
}

// Noop drops events (alerting disabled).
type Noop struct{}

func (Noop) Enabled() bool                            { return false }
func (Noop) Notify(context.Context, DriftEvent) error { return nil }

// Webhook posts drift events to a chat/SOAR endpoint. Format "slack" sends a
// Slack-compatible `{"text": …}` message (also works for Mattermost/Discord-ish
// receivers); "generic" POSTs the raw DriftEvent JSON for SOAR/SIEM consumers.
type Webhook struct {
	url    string
	format string
	client *http.Client
}

// New returns a Webhook notifier, or Noop when url is empty.
func New(url, format string) Notifier {
	if url == "" {
		return Noop{}
	}
	if format == "" {
		format = "slack"
	}
	return &Webhook{url: url, format: format, client: &http.Client{Timeout: 10 * time.Second}}
}

func (w *Webhook) Enabled() bool { return true }

func (w *Webhook) Notify(ctx context.Context, ev DriftEvent) error {
	if ev.Empty() {
		return nil
	}
	var payload any
	if w.format == "generic" {
		payload = ev
	} else {
		payload = map[string]string{"text": slackText(ev)}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := httpx.Do(ctx, w.client, http.MethodPost, w.url, nil, "application/json", body, nil); err != nil {
		return fmt.Errorf("drift webhook: %w", err)
	}
	return nil
}

func slackText(ev DriftEvent) string {
	var b strings.Builder
	scope := ev.Tenant
	if scope == "" {
		scope = "default"
	}
	if len(ev.Appeared) > 0 {
		fmt.Fprintf(&b, ":rotating_light: *PerspectiveGraph drift* (tenant `%s`): %d new critical attack path%s\n",
			scope, len(ev.Appeared), plural(len(ev.Appeared)))
		for _, p := range ev.Appeared {
			tags := ""
			if p.RuntimeConfirmed {
				tags += " ⚡runtime"
			}
			if p.KEV {
				tags += " 🔥KEV"
			}
			fmt.Fprintf(&b, "• %s  (%.0f%%)%s\n", p.Route, p.Score*100, tags)
		}
	}
	if len(ev.Resolved) > 0 {
		fmt.Fprintf(&b, ":white_check_mark: %d path%s resolved\n", len(ev.Resolved), plural(len(ev.Resolved)))
	}
	return strings.TrimRight(b.String(), "\n")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// LogDrift emits a structured drift log line (always, regardless of webhook).
func LogDrift(ev DriftEvent) {
	if ev.Empty() {
		return
	}
	slog.Warn("attack-path drift",
		"tenant", ev.Tenant, "appeared", len(ev.Appeared), "resolved", len(ev.Resolved))
}
