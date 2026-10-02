package custodian

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// TestBucketVerdictsAgreeWithAWS puts the collector's reading of real bucket policies next
// to AWS's own. It runs only inside scripts/entrypoints-lab-aws.sh, which builds the buckets
// on a real account and records, for each, the policy and Block Public Access settings as
// Custodian would report them and what GetBucketPolicyStatus says: whether S3 itself
// counts the policy as public. Anywhere else it skips.
func TestBucketVerdictsAgreeWithAWS(t *testing.T) {
	path := os.Getenv("PG_LAB_BUCKETS")
	if path == "" {
		t.Skip("run by scripts/entrypoints-lab-aws.sh, which builds the buckets and asks AWS about them")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- a path the lab script hands over
	if err != nil {
		t.Fatal(err)
	}
	var lab struct {
		Account string `json:"account"`
		Buckets []struct {
			Name      string          `json:"name"`
			Policy    string          `json:"policy"`
			BPA       map[string]bool `json:"bpa"`
			AWSPublic bool            `json:"aws_public"`
		} `json:"buckets"`
	}
	if err := json.Unmarshal(raw, &lab); err != nil {
		t.Fatal(err)
	}
	if len(lab.Buckets) == 0 {
		t.Fatal("the lab recorded no buckets")
	}
	bucket := func(resource map[string]any) (ontology.Node, []ontology.Edge) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"account_id": lab.Account, "policies": []any{
			map[string]any{"resource": "aws.s3", "resources": []any{resource}},
		}})
		ev := parseBundle(t, string(body))
		for _, n := range ev.Nodes {
			if n.Label == ontology.LabelBucket {
				return n, ev.Edges
			}
		}
		t.Fatalf("no bucket node for %v", resource["Name"])
		return ontology.Node{}, nil
	}
	for _, b := range lab.Buckets {
		short := b.Name[strings.LastIndex(b.Name, "-")+1:]
		// GetBucketPolicyStatus judges the policy alone, so the engine is asked about the
		// policy alone first.
		n, edges := bucket(map[string]any{"Name": b.Name, "Policy": b.Policy})
		got := n.Bool(ontology.PropInternetExposed)
		verdict := "agree"
		if got != b.AWSPublic {
			verdict = "DISAGREE"
			t.Errorf("%s: AWS says public=%v, the engine says %v (policy %s)", short, b.AWSPublic, got, b.Policy)
		}
		t.Logf("%-9s AWS public=%-5v engine public=%-5v %s", short, b.AWSPublic, got, verdict)

		// With the bucket's real settings, RestrictPublicBuckets keeps strangers out of a
		// public policy - which is how the lab keeps its public policies harmless.
		if b.BPA["RestrictPublicBuckets"] {
			guarded, _ := bucket(map[string]any{"Name": b.Name, "Policy": b.Policy, "c7n:PublicAccessBlock": b.BPA})
			if guarded.Bool(ontology.PropInternetExposed) {
				t.Errorf("%s: RestrictPublicBuckets is on, yet the engine calls the bucket exposed", short)
			}
		}
		if short == "grantee" {
			reached := false
			for _, e := range edges {
				reached = reached || (e.Type == ontology.EdgeHasPermission && e.To == n.ID)
			}
			if !reached {
				t.Errorf("grantee: the role the policy names does not reach the bucket")
			}
		}
	}
}
