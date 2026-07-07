package azure

import (
	"context"
	"fmt"
)

// Config selects and configures the Azure connector's transport.
type Config struct {
	// Mode is "fixtures" (default, demo/test from local normalized Azure JSON).
	// "sdk" (live Azure via azure-sdk-for-go) is the wired extension point and is
	// not built into this binary yet - fixtures prove the pull and mapping without
	// credentials or a heavy SDK dependency.
	Mode string
	// FixturesDir is the directory of normalized Azure JSON for fixtures mode.
	FixturesDir string
}

// NewFromConfig builds the Azure connector with the transport chosen by cfg.Mode.
func NewFromConfig(_ context.Context, cfg Config) (*Connector, error) {
	switch cfg.Mode {
	case "", "fixtures":
		return New(Fixtures(cfg.FixturesDir)), nil
	case "sdk":
		return nil, fmt.Errorf("azure connector sdk mode is not wired yet - use fixtures (feed `az network`/`az vm -o json` through the normalized shape) until the live SDK transport is added")
	default:
		return nil, fmt.Errorf("unknown azure connector mode %q (want fixtures)", cfg.Mode)
	}
}
