// Package ai is the AI-native layer: it turns the attack graph into natural
// language — answer a question, brief the board, or explain a path in plain
// English.
//
// Two providers are supported, selected by which credential is set:
//   - Anthropic (Claude) — the preferred backend, via a hand-rolled call to
//     /v1/messages.
//   - HuggingFace (or any OpenAI-compatible endpoint) — for operators who want to
//     use a free/self-hosted model, via the OpenAI-style /chat/completions schema.
//
// Both transports are hand-rolled over the project's httpx helper — no SDK, no
// new dependencies, consistent with the "pure Go, easy to audit" posture of the
// rest of the engine. The layer is self-gated: with no credential the Nop client
// reports Enabled()=false and the API returns 503. Note the trust boundary — the
// graph IS the org's attack map, so sending a compacted view of it to an external
// model is a deliberate operator choice, and every AI call is audited at the API
// layer.
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/httpx"
)

const (
	// defaultModel pins the latest, most capable Claude model.
	defaultModel   = "claude-opus-4-8"
	defaultBaseURL = "https://api.anthropic.com"
	defaultMaxTok  = 4096
	anthropicVer   = "2023-06-01"

	// HuggingFace defaults: its Inference-Providers router speaks the OpenAI
	// chat-completions schema, so the same client serves any OpenAI-compatible
	// endpoint. The model must be one the token can reach — override with HF_MODEL.
	defaultHFModel   = "meta-llama/Llama-3.1-8B-Instruct"
	defaultHFBaseURL = "https://router.huggingface.co/v1"
)

// Client turns a system + user prompt into a text completion.
type Client interface {
	Enabled() bool
	Complete(ctx context.Context, system, user string) (string, error)
}

// Config configures the AI layer. Anthropic (APIKey) takes precedence; if it is
// empty but HFToken is set, the OpenAI-compatible HuggingFace client is used.
type Config struct {
	// Anthropic (Claude) — preferred when set.
	APIKey    string
	Model     string // default claude-opus-4-8
	BaseURL   string // default https://api.anthropic.com (override for a proxy)
	MaxTokens int    // default 4096; shared by both providers

	// HuggingFace / OpenAI-compatible — used when APIKey is empty.
	HFToken   string
	HFModel   string // default meta-llama/Llama-3.1-8B-Instruct (override with HF_MODEL)
	HFBaseURL string // default https://router.huggingface.co/v1
}

// New selects a provider by credential: Anthropic when APIKey is set, else
// HuggingFace (OpenAI-compatible) when HFToken is set, else a disabled Nop.
func New(cfg Config) Client {
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = defaultMaxTok
	}
	switch {
	case cfg.APIKey != "":
		if cfg.Model == "" {
			cfg.Model = defaultModel
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = defaultBaseURL
		}
		return &claude{cfg: cfg, http: &http.Client{Timeout: 90 * time.Second}}
	case cfg.HFToken != "":
		if cfg.HFModel == "" {
			cfg.HFModel = defaultHFModel
		}
		if cfg.HFBaseURL == "" {
			cfg.HFBaseURL = defaultHFBaseURL
		}
		return &openAICompat{cfg: cfg, http: &http.Client{Timeout: 90 * time.Second}}
	default:
		return nop{}
	}
}

// Provider reports the active backend ("anthropic" | "huggingface" | "none") and
// the model id, for startup logging. It never reveals the credential.
func Provider(cfg Config) (provider, model string) {
	switch {
	case cfg.APIKey != "":
		if cfg.Model == "" {
			return "anthropic", defaultModel
		}
		return "anthropic", cfg.Model
	case cfg.HFToken != "":
		if cfg.HFModel == "" {
			return "huggingface", defaultHFModel
		}
		return "huggingface", cfg.HFModel
	default:
		return "none", ""
	}
}

type nop struct{}

func (nop) Enabled() bool { return false }
func (nop) Complete(context.Context, string, string) (string, error) {
	return "", errors.New("AI features are not configured (set ANTHROPIC_API_KEY, or HF_TOKEN for HuggingFace)")
}

type claude struct {
	cfg  Config
	http *http.Client
}

func (c *claude) Enabled() bool { return true }

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type request struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []message `json:"messages"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type response struct {
	Content    []contentBlock `json:"content"`
	StopReason string         `json:"stop_reason"`
}

// Complete sends a single non-streaming message and returns the concatenated
// text blocks. A safety refusal (HTTP 200, stop_reason "refusal") is surfaced as
// an error rather than empty output.
func (c *claude) Complete(ctx context.Context, system, user string) (string, error) {
	body, err := json.Marshal(request{
		Model:     c.cfg.Model,
		MaxTokens: c.cfg.MaxTokens,
		System:    system,
		Messages:  []message{{Role: "user", Content: user}},
	})
	if err != nil {
		return "", err
	}
	headers := map[string]string{
		"x-api-key":         c.cfg.APIKey,
		"anthropic-version": anthropicVer,
	}
	var resp response
	if err := httpx.Do(ctx, c.http, http.MethodPost, c.cfg.BaseURL+"/v1/messages", headers, "application/json", body, &resp); err != nil {
		return "", fmt.Errorf("claude: %w", err)
	}
	if resp.StopReason == "refusal" {
		return "", errors.New("the model declined to answer this request")
	}
	var sb strings.Builder
	for _, b := range resp.Content {
		if b.Type == "text" {
			sb.WriteString(b.Text)
		}
	}
	out := strings.TrimSpace(sb.String())
	if out == "" {
		return "", errors.New("empty response from the model")
	}
	return out, nil
}

// ── HuggingFace / OpenAI-compatible ─────────────────────────────────────

type openAICompat struct {
	cfg  Config
	http *http.Client
}

func (o *openAICompat) Enabled() bool { return true }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model     string        `json:"model"`
	MaxTokens int           `json:"max_tokens"`
	Messages  []chatMessage `json:"messages"`
}

type chatChoice struct {
	Message      chatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

type chatResponse struct {
	Choices []chatChoice `json:"choices"`
}

// Complete sends a single non-streaming chat completion in the OpenAI schema —
// which HuggingFace's Inference-Providers router (and any OpenAI-compatible
// endpoint) accepts — and returns the assistant message text. The system prompt,
// when present, is sent as the leading system message.
func (o *openAICompat) Complete(ctx context.Context, system, user string) (string, error) {
	msgs := make([]chatMessage, 0, 2)
	if system != "" {
		msgs = append(msgs, chatMessage{Role: "system", Content: system})
	}
	msgs = append(msgs, chatMessage{Role: "user", Content: user})

	body, err := json.Marshal(chatRequest{
		Model:     o.cfg.HFModel,
		MaxTokens: o.cfg.MaxTokens,
		Messages:  msgs,
	})
	if err != nil {
		return "", err
	}
	headers := map[string]string{"Authorization": "Bearer " + o.cfg.HFToken}
	var resp chatResponse
	if err := httpx.Do(ctx, o.http, http.MethodPost, o.cfg.HFBaseURL+"/chat/completions", headers, "application/json", body, &resp); err != nil {
		return "", fmt.Errorf("huggingface: %w", err)
	}
	if len(resp.Choices) == 0 {
		return "", errors.New("empty response from the model")
	}
	out := strings.TrimSpace(resp.Choices[0].Message.Content)
	if out == "" {
		return "", errors.New("empty response from the model")
	}
	return out, nil
}
