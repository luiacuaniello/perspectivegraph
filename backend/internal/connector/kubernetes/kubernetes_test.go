package kubernetes

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/k8s"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// fakeAPI serves a dump the way an API server would: one list endpoint per kind, items
// without the kind and apiVersion a kubectl List puts on them, paged two at a time, and
// only to the bearer token it was told to expect.
type fakeAPI struct {
	srv       *httptest.Server
	caFile    string
	tokenFile string

	mu        sync.Mutex
	token     string
	forbidden map[string]bool // paths answered 403
	awsAuth   json.RawMessage
	tokens    []string // every token presented, in order
}

func newFakeAPI(t *testing.T, dump []byte) *fakeAPI {
	t.Helper()
	var list struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(dump, &list); err != nil {
		t.Fatal(err)
	}
	byPath := map[string][]map[string]json.RawMessage{}
	for _, it := range list.Items {
		var kind string
		_ = json.Unmarshal(it["kind"], &kind)
		for _, k := range kinds {
			if k.kind == kind {
				delete(it, "kind")
				delete(it, "apiVersion")
				byPath[k.path] = append(byPath[k.path], it)
			}
		}
	}

	f := &fakeAPI{token: "token-1", forbidden: map[string]bool{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.tokens = append(f.tokens, got)
		if got != f.token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.forbidden[r.URL.Path] {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"kind":"Status","message":"clusterrolebindings is forbidden"}`))
			return
		}
		if r.URL.Path == awsAuthPath {
			if f.awsAuth == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(f.awsAuth)
			return
		}
		items := byPath[r.URL.Path]
		start, _ := strconv.Atoi(r.URL.Query().Get("continue"))
		end := min(start+2, len(items))
		page := map[string]any{"kind": "List", "items": items[start:end], "metadata": map[string]string{}}
		if end < len(items) {
			page["metadata"] = map[string]string{"continue": strconv.Itoa(end)}
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(f.srv.Close)

	dir := t.TempDir()
	f.caFile = filepath.Join(dir, "ca.crt")
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	if err := os.WriteFile(f.caFile, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	f.tokenFile = filepath.Join(dir, "token")
	f.rotate(t, "token-1")
	return f
}

func (f *fakeAPI) rotate(t *testing.T, token string) {
	t.Helper()
	f.mu.Lock()
	f.token = token
	f.mu.Unlock()
	if err := os.WriteFile(f.tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sample(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../../testdata/k8s-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// shape is what an event stream says, order and timestamps aside.
func shape(evs []ontology.Event) []string {
	var out []string
	for _, ev := range evs {
		for _, n := range ev.Nodes {
			props, _ := json.Marshal(n.Properties)
			out = append(out, "node "+n.ID+" "+string(n.Label)+" "+n.Name+" "+string(props))
		}
		for _, e := range ev.Edges {
			out = append(out, "edge "+string(e.Type)+" "+e.From+" "+e.To)
		}
	}
	sort.Strings(out)
	return out
}

// The point of the connector: what it reads from the API comes out of the collector exactly
// as the same objects posted as a kubectl dump do - every node, property and edge.
func TestReadingTheAPIFindsWhatAPostedDumpFinds(t *testing.T) {
	dump := sample(t)
	api := newFakeAPI(t, dump)
	tr, err := newInCluster(api.srv.URL, api.caFile, api.tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	conn := New(tr, "prod-eu", "")

	got, err := conn.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	want, err := k8s.New().Parse(bytes.NewReader(dump), ingestion.Options{Cluster: "prod-eu"})
	if err != nil {
		t.Fatal(err)
	}
	gs, ws := shape(got), shape(want)
	if len(ws) == 0 {
		t.Fatal("the sample produced nothing to compare")
	}
	if strings.Join(gs, "\n") != strings.Join(ws, "\n") {
		t.Errorf("the connector and a posted dump disagree:\n got %d lines\nwant %d lines\nfirst got:  %v\nfirst want: %v", len(gs), len(ws), gs[:min(3, len(gs))], ws[:min(3, len(ws))])
	}
	for _, ev := range got {
		if ev.Snapshot == nil || ev.Snapshot.Scope != "cluster:prod-eu" {
			t.Fatalf("a complete pull must declare the cluster's snapshot, got %+v", ev.Snapshot)
		}
	}
}

// A kind that cannot be listed leaves the pull incomplete: what was read is returned, with
// the error, but no snapshot - so nothing the refused list would have shown is retracted.
func TestARefusedKindRetractsNothing(t *testing.T) {
	api := newFakeAPI(t, sample(t))
	api.forbidden["/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"] = true
	tr, err := newInCluster(api.srv.URL, api.caFile, api.tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	evs, err := New(tr, "prod-eu", "").Collect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ClusterRoleBinding") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want the refused kind named", err)
	}
	if len(evs) == 0 {
		t.Fatal("the kinds that could be read were dropped")
	}
	for _, ev := range evs {
		if ev.Snapshot != nil {
			t.Fatal("an incomplete pull declared a snapshot: it would retract every binding")
		}
	}
}

// The token is read on every pull: the one Kubernetes projects into a pod is rotated, and
// a token held from startup would expire within hours.
func TestTheTokenIsReadOnEveryPull(t *testing.T) {
	api := newFakeAPI(t, sample(t))
	tr, err := newInCluster(api.srv.URL, api.caFile, api.tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tr.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	api.rotate(t, "token-2")
	if _, _, err := tr.Fetch(context.Background()); err != nil {
		t.Fatalf("the pull after a rotation failed: %v", err)
	}
	if last := api.tokens[len(api.tokens)-1]; last != "token-2" {
		t.Errorf("last pull presented %q", last)
	}
}

// EKS's aws-auth map is read when it exists, and its absence is not an error: most
// clusters are not EKS, and EKS clusters on access entries alone have none.
func TestAwsAuthIsReadWhenThereIsOne(t *testing.T) {
	api := newFakeAPI(t, sample(t))
	tr, err := newInCluster(api.srv.URL, api.caFile, api.tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	raw, complete, err := tr.Fetch(context.Background())
	if err != nil || !complete || strings.Contains(string(raw), `"aws-auth"`) {
		t.Fatalf("without aws-auth: complete=%v err=%v", complete, err)
	}
	api.awsAuth = json.RawMessage(`{"metadata":{"name":"aws-auth","namespace":"kube-system"},"data":{"mapRoles":""}}`)
	raw, complete, err = tr.Fetch(context.Background())
	if err != nil || !complete || !strings.Contains(string(raw), `"ConfigMap"`) {
		t.Fatalf("with aws-auth: complete=%v err=%v", complete, err)
	}
}

// The server is verified against the cluster's CA: an answer signed by anything else is
// refused rather than read.
func TestAServerOutsideTheClustersCAIsRefused(t *testing.T) {
	api := newFakeAPI(t, sample(t))
	// Every httptest server shares one built-in certificate, so the impostor gets one of
	// its own: same address, a key the cluster's CA never signed.
	other := httptest.NewUnstartedServer(http.NotFoundHandler())
	other.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}, MinVersion: tls.VersionTLS12}
	other.StartTLS()
	defer other.Close()
	tr, err := newInCluster(other.URL, api.caFile, api.tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tr.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("err = %v, want a certificate error", err)
	}
}

// Fixtures serve the sample dump, complete, so the demo pulls a cluster without one.
func TestFixturesServeTheSampleDump(t *testing.T) {
	conn, err := NewFromConfig(Config{Mode: "fixtures", Cluster: "demo", FixturesDir: "../../../testdata"})
	if err != nil {
		t.Fatal(err)
	}
	evs, err := conn.Collect(context.Background())
	if err != nil || len(evs) == 0 {
		t.Fatalf("evs=%d err=%v", len(evs), err)
	}
	if evs[0].Snapshot == nil || evs[0].Snapshot.Scope != "cluster:demo" {
		t.Errorf("snapshot %+v", evs[0].Snapshot)
	}
}

func TestConfigRefusesWhatCannotWork(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	for name, cfg := range map[string]Config{
		"no cluster name":    {Mode: "fixtures"},
		"a name with spaces": {Mode: "fixtures", Cluster: "prod eu"},
		"an unknown mode":    {Mode: "kubeconfig", Cluster: "prod"},
		"outside a pod":      {Mode: "incluster", Cluster: "prod"},
	} {
		if _, err := NewFromConfig(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// selfSigned is a certificate for 127.0.0.1 that no CA in the test signed.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "impostor"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The chart grants what the connector reads, and nothing more: a kind read but not granted
// fails every pull with a 403, and one granted but not read is access nothing uses - in a
// role that reads a whole cluster, the second matters as much as the first.
func TestTheChartGrantsExactlyWhatIsRead(t *testing.T) {
	tpl, err := os.ReadFile("../../../../deploy/helm/perspectivegraph/templates/kubernetes-reader.yaml")
	if err != nil {
		t.Fatal(err)
	}
	granted := map[string]bool{}
	for _, m := range regexp.MustCompile(`resources: \[([^\]]*)\]`).FindAllStringSubmatch(string(tpl), -1) {
		for _, r := range strings.Split(m[1], ",") {
			granted[strings.TrimSpace(r)] = true
		}
	}
	read := map[string]bool{"configmaps": true} // aws-auth, by name
	for _, k := range kinds {
		read[k.path[strings.LastIndex(k.path, "/")+1:]] = true
	}
	for r := range read {
		if !granted[r] {
			t.Errorf("the connector reads %s, which the chart does not grant", r)
		}
	}
	for r := range granted {
		if !read[r] {
			t.Errorf("the chart grants %s, which the connector never reads", r)
		}
	}
	for _, m := range regexp.MustCompile(`verbs: \[([^\]]*)\]`).FindAllStringSubmatch(string(tpl), -1) {
		for _, v := range strings.Split(m[1], ",") {
			if v = strings.TrimSpace(v); v != "get" && v != "list" {
				t.Errorf("the chart grants the verb %q: the connector only reads", v)
			}
		}
	}
	if !strings.Contains(string(tpl), "resourceNames: [aws-auth]") {
		t.Error("config maps must be granted by name - aws-auth - not all of them")
	}
}
