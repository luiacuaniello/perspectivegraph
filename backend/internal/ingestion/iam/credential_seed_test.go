package iam

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// TestSeedIAMUsersOptIn proves credential-origin seeding is OFF by default and marks IAM
// users as seeds (credential_exposed) only when the operator opts in.
func TestSeedIAMUsersOptIn(t *testing.T) {
	const bundle = `{"UserDetailList":[{"UserName":"alice","Arn":"arn:aws:iam::1:user/alice"}]}`
	userSeed := func() (found, seed bool) {
		events, err := New().Parse(strings.NewReader(bundle), ingestion.Options{})
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range events[0].Nodes {
			if n.Label == ontology.LabelUser && n.Name == "alice" {
				return true, n.Bool(ontology.PropCredentialExposed)
			}
		}
		return false, false
	}
	t.Cleanup(func() { SetSeedIAMUsers(false) }) // do not leak the toggle to other tests

	SetSeedIAMUsers(false)
	if found, seed := userSeed(); !found || seed {
		t.Errorf("default: found=%v credential_exposed=%v, want found=true seed=false", found, seed)
	}

	SetSeedIAMUsers(true)
	if found, seed := userSeed(); !found || !seed {
		t.Errorf("opt-in: found=%v credential_exposed=%v, want found=true seed=true", found, seed)
	}
}
