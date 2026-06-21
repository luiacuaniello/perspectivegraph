package config

import (
	"testing"
	"time"
)

func TestGetdurRejectsNonPositiveAndMalformed(t *testing.T) {
	const def = 30 * time.Second
	cases := map[string]time.Duration{
		"10s":    10 * time.Second, // valid value wins
		"0s":     def,              // zero would panic time.NewTicker
		"-5s":    def,              // negative likewise
		"banana": def,              // malformed
		"":       def,              // empty → default
		"1m30s":  90 * time.Second, // composite durations parse
	}
	for val, want := range cases {
		t.Setenv("TEST_INTERVAL", val)
		if got := getdur("TEST_INTERVAL", def); got != want {
			t.Errorf("getdur(%q) = %v, want %v", val, got, want)
		}
	}
}
