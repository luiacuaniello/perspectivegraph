package aws

import (
	"context"
	"fmt"
)

// Config selects and configures the AWS connector's transport.
type Config struct {
	// Mode is "fixtures" (default, demo/test from local JSON) or "sdk" (live
	// AWS via aws-sdk-go-v2).
	Mode string
	// FixturesDir is the directory of describe-* JSON for fixtures mode.
	FixturesDir string
	// Region and RoleARN configure sdk mode: the AWS region and an optional
	// cross-account read-only role to assume (the "customer grants you a role"
	// agentless model).
	Region  string
	RoleARN string
}

// NewFromConfig builds the AWS connector with the transport chosen by cfg.Mode:
// "fixtures" (local describe-* JSON, no credentials) or "sdk" (live AWS via
// aws-sdk-go-v2; read-only, optional cross-account AssumeRole).
func NewFromConfig(ctx context.Context, cfg Config) (*Connector, error) {
	switch cfg.Mode {
	case "sdk":
		t, err := newSDK(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return New(t), nil
	case "", "fixtures":
		return New(Fixtures(cfg.FixturesDir)), nil
	default:
		return nil, fmt.Errorf("unknown aws connector mode %q (want fixtures|sdk)", cfg.Mode)
	}
}
