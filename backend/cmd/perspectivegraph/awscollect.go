package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	awsconn "github.com/luiacuaniello/perspectivegraph/internal/connector/aws"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// runAwsCollect runs the live AWS connector (sdk transport) ONCE against a real
// account and shows what it discovered - the read-only "does the connector read my
// real VPC correctly?" validation primitive, without standing up the whole service:
//
//	perspectivegraph awscollect -region eu-west-1                 # ambient creds
//	perspectivegraph awscollect -region eu-west-1 -role arn:aws:iam::123:role/pg-ro
//	perspectivegraph awscollect -region eu-west-1 -json           # raw events, pipe-able
//	perspectivegraph awscollect -region eu-west-1 -ingest http://localhost:8081
//
// It uses the standard AWS credential chain (env / profile / IRSA / instance role),
// optionally assuming a cross-account read-only role first. The summary makes the
// reachability precision visible on real data: it lists both the internet-exposed
// seeds AND the SG-open instances the route/NACL layer *suppressed* (with the reason),
// which is exactly the false-positive removal that has to hold on a real account. With
// -ingest it POSTs the discovered events into a running stack for full path scoring.
func runAwsCollect(args []string) error {
	fs := flag.NewFlagSet("awscollect", flag.ContinueOnError)
	region := fs.String("region", os.Getenv("AWS_REGION"), "AWS region to collect (defaults to $AWS_REGION)")
	role := fs.String("role", "", "optional cross-account read-only role ARN to assume first")
	ingest := fs.String("ingest", "", "if set, POST the discovered events to this ingest base URL for full path scoring")
	token := fs.String("token", os.Getenv("API_TOKEN"), "bearer token if ingest auth is on")
	asJSON := fs.Bool("json", false, "print the raw discovered events as JSON instead of a summary")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	conn, err := awsconn.NewFromConfig(ctx, awsconn.Config{Mode: "sdk", Region: *region, RoleARN: *role})
	if err != nil {
		return fmt.Errorf("build sdk connector: %w", err)
	}
	events, err := conn.Collect(ctx)
	if err != nil {
		// Collect joins per-feed errors but still returns partial events, so surface the
		// error as a warning rather than dropping what did come back.
		fmt.Fprintf(os.Stderr, "awscollect: partial collect: %v\n", err)
	}

	if *asJSON {
		b, err := json.MarshalIndent(events, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	printAwsSummary(*region, *role, events)

	if *ingest != "" {
		body, err := json.Marshal(events)
		if err != nil {
			return err
		}
		client := &http.Client{Timeout: 60 * time.Second}
		st, rb, err := apiRequest(client, http.MethodPost, *ingest+"/ingest/events", *token, body)
		if err != nil {
			return fmt.Errorf("POST /ingest/events: %w", err)
		}
		if st >= 300 {
			return fmt.Errorf("POST /ingest/events returned %d: %s", st, string(rb))
		}
		fmt.Printf("\n  ingested %d events → give the analyzer a pass, then query attackPaths.\n", len(events))
	}
	return nil
}

func printAwsSummary(region, role string, events []ontology.Event) {
	var nodes, edges int
	byLabel := map[ontology.Label]int{}
	var exposed, suppressed, jewels []string
	for _, ev := range events {
		edges += len(ev.Edges)
		for _, n := range ev.Nodes {
			nodes++
			byLabel[n.Label]++
			if n.Bool(ontology.PropInternetExposed) {
				exposed = append(exposed, n.Name)
			} else if note, _ := n.Properties["net_reachability"].(string); note != "" {
				suppressed = append(suppressed, fmt.Sprintf("%s: %s", n.Name, note))
			}
			if n.Bool(ontology.PropCrownJewel) {
				jewels = append(jewels, n.Name)
			}
		}
	}
	sort.Strings(exposed)
	sort.Strings(suppressed)
	sort.Strings(jewels)

	target := region
	if target == "" {
		target = "(default region)"
	}
	if role != "" {
		target += ", role=" + role
	}
	fmt.Printf("awscollect (sdk mode, %s): %d nodes, %d edges\n", target, nodes, edges)
	fmt.Printf("  by label: VMs=%d VPCs=%d Users=%d Roles=%d\n",
		byLabel[ontology.LabelVirtualMachine], byLabel[ontology.LabelVPC],
		byLabel[ontology.LabelUser], byLabel[ontology.LabelIAMRole])

	printList("internet-exposed seeds", exposed)
	printList("SG-open but NOT exposed (reachability precision suppressed these false positives)", suppressed)
	printList("sensitive assets", jewels)

	if len(exposed) == 0 && len(suppressed) == 0 {
		fmt.Println("\n  no internet-open security groups found - nothing to gate on reachability in this account/region.")
	}
	fmt.Println("\n  eyeball the two lists against what you know of the account: the 'exposed' set")
	fmt.Println("  should be genuinely reachable, the 'suppressed' set genuinely private.")
	fmt.Println("  push into a running stack for full attack-path scoring with -ingest http://localhost:8081.")
}

func printList(title string, items []string) {
	fmt.Printf("\n  %s (%d):\n", title, len(items))
	for _, it := range items {
		fmt.Printf("    - %s\n", it)
	}
}
