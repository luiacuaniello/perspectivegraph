package auth

import (
	"bytes"
	"io"
	"net/http"
)

// readAll reads up to max bytes of the request body (for signature checking).
func readAll(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, max))
}

// restoreBody puts the already-read body back so the next handler can read it.
func restoreBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
}
