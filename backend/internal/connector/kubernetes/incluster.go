package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// serviceAccountDir is where Kubernetes mounts the pod's service account credentials.
const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// pageSize bounds one list call; larger collections are read a page at a time.
const pageSize = 500

// maxPage bounds what one page may weigh, so a misbehaving API server cannot make the
// backend hold an unbounded answer in memory.
const maxPage = 64 << 20

// listed is one kind the connector reads, with the kind and apiVersion a list response
// leaves off its items and a kubectl List puts on each.
type listed struct {
	path, kind, apiVersion string
}

// kinds is what the k8s collector reads from a dump, and so what the chart's ClusterRole
// grants (get, list) - and nothing else: no secrets, no config maps but aws-auth.
var kinds = []listed{
	{"/api/v1/pods", "Pod", "v1"},
	{"/api/v1/services", "Service", "v1"},
	{"/api/v1/serviceaccounts", "ServiceAccount", "v1"},
	{"/api/v1/nodes", "Node", "v1"},
	{"/apis/networking.k8s.io/v1/ingresses", "Ingress", "networking.k8s.io/v1"},
	{"/apis/rbac.authorization.k8s.io/v1/roles", "Role", "rbac.authorization.k8s.io/v1"},
	{"/apis/rbac.authorization.k8s.io/v1/clusterroles", "ClusterRole", "rbac.authorization.k8s.io/v1"},
	{"/apis/rbac.authorization.k8s.io/v1/rolebindings", "RoleBinding", "rbac.authorization.k8s.io/v1"},
	{"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", "ClusterRoleBinding", "rbac.authorization.k8s.io/v1"},
}

// awsAuthPath is EKS's map from IAM roles and users to Kubernetes identities. A cluster
// that is not EKS, or that uses access entries alone, has none.
const awsAuthPath = "/api/v1/namespaces/kube-system/configmaps/aws-auth"

// inCluster reads the cluster's API as the pod's service account. Hand-rolled on net/http
// rather than client-go: nine list calls and one get do not justify the dependency tree.
type inCluster struct {
	base      string
	tokenFile string
	client    *http.Client
}

// InCluster returns the transport for the cluster the backend runs in: the API server the
// kubelet names in KUBERNETES_SERVICE_HOST/PORT, verified against the cluster's CA, and
// the service account's token.
func InCluster() (transport, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("not running in a Kubernetes pod (KUBERNETES_SERVICE_HOST is unset): the incluster mode reads the cluster the backend runs in")
	}
	return newInCluster("https://"+net.JoinHostPort(host, port),
		serviceAccountDir+"/ca.crt", serviceAccountDir+"/token")
}

func newInCluster(base, caFile, tokenFile string) (*inCluster, error) {
	pem, err := os.ReadFile(caFile) // #nosec G304 -- the service account's own mount, or a test's
	if err != nil {
		return nil, fmt.Errorf("the cluster's CA (%s): %w - is a service account token mounted? (automountServiceAccountToken)", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no certificate", caFile)
	}
	if _, err := os.Stat(tokenFile); err != nil {
		return nil, fmt.Errorf("the service account token (%s): %w", tokenFile, err)
	}
	return &inCluster{
		base:      strings.TrimSuffix(base, "/"),
		tokenFile: tokenFile,
		client: &http.Client{
			Timeout:   time.Minute,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

func (c *inCluster) Mode() string { return "incluster" }

// Fetch lists every kind, then aws-auth. A kind that cannot be listed is reported and
// leaves the pull incomplete; the others are still returned.
func (c *inCluster) Fetch(ctx context.Context) ([]byte, bool, error) {
	// Read on every pull, not once: the token Kubernetes projects into the pod is rotated,
	// and one held from startup expires within hours.
	tok, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return nil, false, fmt.Errorf("service account token: %w", err)
	}
	token := strings.TrimSpace(string(tok))

	var items []json.RawMessage
	var errs []error
	complete := true
	for _, k := range kinds {
		got, err := c.list(ctx, token, k)
		if err != nil {
			errs = append(errs, err)
			complete = false
			continue
		}
		items = append(items, got...)
	}
	cm, found, err := c.get(ctx, token, awsAuthPath, "ConfigMap", "v1")
	switch {
	case err != nil:
		errs = append(errs, err)
		complete = false
	case found:
		items = append(items, cm)
	}
	if len(items) == 0 {
		return nil, false, errors.Join(errs...)
	}
	raw, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "List", "items": items})
	if err != nil {
		return nil, false, err
	}
	return raw, complete, errors.Join(errs...)
}

// list reads one kind across every namespace, a page at a time.
func (c *inCluster) list(ctx context.Context, token string, k listed) ([]json.RawMessage, error) {
	var out []json.RawMessage
	cont := ""
	for {
		q := url.Values{"limit": {fmt.Sprint(pageSize)}}
		if cont != "" {
			q.Set("continue", cont)
		}
		body, status, err := c.do(ctx, token, k.path+"?"+q.Encode())
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", k.kind, err)
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("list %s: %d %s", k.kind, status, reason(body))
		}
		var page struct {
			Items    []json.RawMessage `json:"items"`
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("list %s: %w", k.kind, err)
		}
		for _, it := range page.Items {
			typed, err := withKind(it, k.kind, k.apiVersion)
			if err != nil {
				return nil, fmt.Errorf("list %s: %w", k.kind, err)
			}
			out = append(out, typed)
		}
		if page.Metadata.Continue == "" {
			return out, nil
		}
		cont = page.Metadata.Continue
	}
}

// get reads one object; found is false when it does not exist.
func (c *inCluster) get(ctx context.Context, token, path, kind, apiVersion string) (json.RawMessage, bool, error) {
	body, status, err := c.do(ctx, token, path)
	if err != nil {
		return nil, false, fmt.Errorf("get %s: %w", path, err)
	}
	switch status {
	case http.StatusOK:
		typed, err := withKind(body, kind, apiVersion)
		return typed, err == nil, err
	case http.StatusNotFound:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("get %s: %d %s", path, status, reason(body))
	}
}

func (c *inCluster) do(ctx context.Context, token, path string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPage+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > maxPage {
		return nil, 0, fmt.Errorf("answer larger than %d MiB", maxPage>>20)
	}
	return body, resp.StatusCode, nil
}

// withKind stamps an item with its kind and apiVersion, as kubectl does in a List: a list
// response carries them once, on the list, and the collector reads them per item.
func withKind(item json.RawMessage, kind, apiVersion string) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(item, &obj); err != nil {
		return nil, err
	}
	obj["kind"], _ = json.Marshal(kind)
	obj["apiVersion"], _ = json.Marshal(apiVersion)
	return json.Marshal(obj)
}

// reason is the message of a Kubernetes Status answer, or the start of whatever came back.
func reason(body []byte) string {
	var st struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &st) == nil && st.Message != "" {
		return st.Message
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
