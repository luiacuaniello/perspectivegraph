// Package httpx is the minimal JSON-over-HTTP helper shared by the action
// layer (forge REST APIs) and the search indexer (OpenSearch) — one request/
// status-check/decode implementation instead of a copy per package.
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// maxRespBytes caps the response body we buffer/decode, so a hostile or
// misbehaving upstream (JWKS, forge API, OpenSearch) can't exhaust memory with
// an unbounded reply. Every caller exchanges small JSON documents.
const maxRespBytes = 16 << 20 // 16 MiB

// Do performs the request and, when out is non-nil, decodes the JSON response
// into it. Non-2xx responses become errors carrying the (truncated) body. The
// caller's client SHOULD set a Timeout (or the ctx a deadline); the response
// body is size-capped regardless.
func Do(ctx context.Context, client *http.Client, method, url string, headers map[string]string, contentType string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("%s %s: %s: %s", method, url, resp.Status, bytes.TrimSpace(msg))
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, maxRespBytes)).Decode(out)
	}
	return nil
}
