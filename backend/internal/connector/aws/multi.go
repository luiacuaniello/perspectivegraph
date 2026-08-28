package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// multiConnector collects several AWS accounts as one source.
//
// A real estate is not one account, and the connector's shape - one transport, one set
// of credentials, one account - is right per account and wrong for the estate. Rather
// than teach the transport to be several accounts at once, this fans out over one
// connector per account and concatenates what they return. The scheduler above still
// sees a single "aws" source, so nothing downstream learns a new concept.
type multiConnector struct {
	accounts []*Connector
}

// Mode reports the shared transport mode plus how many accounts are behind it, because
// "sdk" alone in a status endpoint does not tell an operator whether the second account
// they configured is actually being read.
func (m *multiConnector) Mode() string {
	if len(m.accounts) == 0 {
		return "sdk"
	}
	return fmt.Sprintf("%s x%d accounts", m.accounts[0].Mode(), len(m.accounts))
}

func (*multiConnector) Source() string { return "aws" }

// Collect pulls every account. One account failing does not sink the rest: its error is
// joined and the others' events are still returned, for the same reason a failed feed
// does not sink its siblings. An estate where one role has expired should lose that
// account's assets for a pass, not the whole picture.
func (m *multiConnector) Collect(ctx context.Context) ([]ontology.Event, error) {
	var (
		out  []ontology.Event
		errs []error
	)
	for _, c := range m.accounts {
		evs, err := c.Collect(ctx)
		if err != nil {
			errs = append(errs, err)
		}
		out = append(out, evs...)
	}
	return out, errors.Join(errs...)
}

// splitARNs parses the comma-separated role list. Empty entries are dropped rather than
// turned into "the current account", so a trailing comma or a copied-in blank cannot
// silently add a whole account's worth of assets to the pull.
func splitARNs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
