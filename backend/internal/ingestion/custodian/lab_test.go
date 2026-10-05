package custodian

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// labRow appends one check to the rows file a lab script turns into its record
// (scripts/lab-record.py), when the script names one: the question, AWS's answer, the
// engine's, and whether they agree.
func labRow(t *testing.T, check map[string]string) {
	t.Helper()
	path := os.Getenv("PG_LAB_ROWS")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- a path the lab script hands over
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(check); err != nil {
		t.Fatal(err)
	}
}

func agreement(agree bool) string {
	if agree {
		return "agree"
	}
	return "disagree"
}

func publicWord(public bool) string {
	if public {
		return "public"
	}
	return "not public"
}

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
		labRow(t, map[string]string{"case": short, "question": "Does S3 count this bucket policy as public?",
			"referee": "S3 GetBucketPolicyStatus", "aws": publicWord(b.AWSPublic), "engine": publicWord(got),
			"verdict": agreement(got == b.AWSPublic), "note": bucketCaseNote[short]})

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

// TestBlockPublicAccessAgreesWithAWS puts the collector's reading of Block Public Access -
// a bucket's own, and the account's - next to what AWS does with a stranger's request. It
// runs only inside scripts/public-access-lab-aws.sh, which builds two buckets with a policy
// open to anyone, one closed by its own RestrictPublicBuckets and one only by the account's,
// and records for each what GetBucketPolicyStatus says of the policy and what an anonymous
// listing gets. Anywhere else it skips.
func TestBlockPublicAccessAgreesWithAWS(t *testing.T) {
	path := os.Getenv("PG_LAB_PUBLIC_ACCESS")
	if path == "" {
		t.Skip("run by scripts/public-access-lab-aws.sh, which builds the buckets and asks AWS about them")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- a path the lab script hands over
	if err != nil {
		t.Fatal(err)
	}
	var lab struct {
		Account    string          `json:"account"`
		AccountBPA map[string]bool `json:"account_bpa"`
		Buckets    []struct {
			Name            string          `json:"name"`
			Policy          string          `json:"policy"`
			BPA             map[string]bool `json:"bpa"`
			AWSPolicyPublic bool            `json:"aws_policy_public"`
			Anonymous       string          `json:"anonymous"`
		} `json:"buckets"`
	}
	if err := json.Unmarshal(raw, &lab); err != nil {
		t.Fatal(err)
	}
	if len(lab.Buckets) == 0 {
		t.Fatal("the lab recorded no buckets")
	}
	// open is the engine's verdict on a bucket, with or without the account's settings in
	// the export - the aws.account resource Custodian's s3-public-block filter reports.
	open := func(bucket map[string]any, withAccount bool) bool {
		t.Helper()
		policies := []any{map[string]any{"resource": "aws.s3", "resources": []any{bucket}}}
		if withAccount {
			policies = append(policies, map[string]any{"resource": "aws.account", "resources": []any{
				map[string]any{"account_id": lab.Account, "c7n:s3-public-block": lab.AccountBPA},
			}})
		}
		body, _ := json.Marshal(map[string]any{"account_id": lab.Account, "policies": policies})
		for _, n := range parseBundle(t, string(body)).Nodes {
			if n.Label == ontology.LabelBucket {
				return n.InternetExposed()
			}
		}
		t.Fatalf("no bucket node for %v", bucket["Name"])
		return false
	}
	for _, b := range lab.Buckets {
		short := b.Name[strings.LastIndex(b.Name, "-")+1:]
		if !b.AWSPolicyPublic {
			t.Fatalf("%s: GetBucketPolicyStatus calls the policy private, so the lab was not built as intended", short)
		}
		// 200 is a stranger let in; 403 AccessDenied is one kept out. Anything else - a
		// redirect, a timeout - is no verdict, and a lab without one proves nothing.
		strangerIn := strings.HasPrefix(b.Anonymous, "200")
		if !strangerIn && b.Anonymous != "403 AccessDenied" {
			t.Fatalf("%s: the anonymous request gave no verdict: %q", short, b.Anonymous)
		}
		bucket := map[string]any{"Name": b.Name, "Policy": b.Policy, "c7n:PublicAccessBlock": b.BPA}
		got := open(bucket, true)
		verdict := "agree"
		if got != strangerIn {
			verdict = "DISAGREE"
			t.Errorf("%s: a stranger gets %q from AWS, and the engine calls the bucket open=%v", short, b.Anonymous, got)
		}
		t.Logf("%-12s policy public=%-5v stranger gets %-17s engine open=%-5v %s", short, b.AWSPolicyPublic, b.Anonymous, got, verdict)
		closedBy := "its own RestrictPublicBuckets"
		if !b.BPA["RestrictPublicBuckets"] {
			closedBy = "only the account's RestrictPublicBuckets"
		}
		engineSays := "closed"
		if got {
			engineSays = "open"
		}
		labRow(t, map[string]string{"case": short,
			"question": "Does a stranger get into a bucket whose public policy " + closedBy + " closes?",
			"referee":  "an anonymous request to the bucket", "aws": b.Anonymous, "engine": engineSays,
			"verdict": agreement(got == strangerIn)})
		// The account's settings are what close this one: an export without them must err
		// toward reporting it open, which is the false positive reading them removes.
		if !b.BPA["RestrictPublicBuckets"] && lab.AccountBPA["RestrictPublicBuckets"] {
			without := open(bucket, false)
			if !without {
				t.Errorf("%s: told nothing of the account's settings, the engine should report the public policy open", short)
			}
			t.Logf("%-12s without the account's settings in the export, engine open=%v (what 1.31 reported)", short, without)
		}
	}
}

// bucketCaseNote says what each bucket in scripts/entrypoints-lab-aws.sh puts to the test,
// for the record a reader sees.
var bucketCaseNote = map[string]string{
	"open":    "open to anyone, on condition of TLS",
	"referer": "open to anyone with a given Referer",
	"vpcwild": "open to any VPC (vpc-*)",
	"ipfixed": "open to one documentation range",
	"ipbroad": "open to 0.0.0.0/1, half the IPv4 internet",
	"vpce":    "open through one VPC endpoint",
	"account": "open to one account's principals",
	"grantee": "granted to one named role",
	"putonly": "anyone may write, not read",
	"tlsdeny": "open, with a Deny for requests without TLS",
}
