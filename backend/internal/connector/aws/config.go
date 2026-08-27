package aws

import (
	"context"
	"fmt"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Source is what NewFromConfig returns: the scheduler's connector contract plus the
// Mode() the wiring logs. Declared structurally rather than by importing the scheduler,
// so this package keeps depending only on the ontology - and it is an interface rather
// than *Connector because one account and several are different types with the same job.
type Source interface {
	Source() string
	Mode() string
	Collect(ctx context.Context) ([]ontology.Event, error)
}

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
	//
	// RoleARN accepts SEVERAL roles, comma-separated - one per account - because an
	// estate is rarely one account. The single-value and empty forms are untouched:
	// empty reads the ambient credentials' own account, one role reads that role's
	// account, and N roles read N accounts in one pass. Each account's assets are
	// qualified with the account id AWS reports for its credentials, so ids that
	// collide across accounts (i-…, sg-…) stay distinct.
	Region  string
	RoleARN string
}

// NewFromConfig builds the AWS connector with the transport chosen by cfg.Mode:
// "fixtures" (local describe-* JSON, no credentials) or "sdk" (live AWS via
// aws-sdk-go-v2; read-only, optional cross-account AssumeRole).
func NewFromConfig(ctx context.Context, cfg Config) (Source, error) {
	switch cfg.Mode {
	case "sdk":
		roles := splitARNs(cfg.RoleARN)
		if len(roles) <= 1 {
			// One account: the shape this connector has always had.
			t, err := newSDK(ctx, cfg)
			if err != nil {
				return nil, err
			}
			return New(t), nil
		}
		multi := &multiConnector{}
		for _, role := range roles {
			perAccount := cfg
			perAccount.RoleARN = role
			t, err := newSDK(ctx, perAccount)
			if err != nil {
				return nil, fmt.Errorf("account %s: %w", role, err)
			}
			multi.accounts = append(multi.accounts, New(t))
		}
		return multi, nil
	case "", "fixtures":
		return New(Fixtures(cfg.FixturesDir)), nil
	default:
		return nil, fmt.Errorf("unknown aws connector mode %q (want fixtures|sdk)", cfg.Mode)
	}
}
