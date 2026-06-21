package ontology

// Label is the type of a graph vertex (V). The set of labels is the shared
// vocabulary that every collector must map its findings onto.
type Label string

const (
	// Infrastructure
	LabelVirtualMachine Label = "VirtualMachine"
	LabelContainer      Label = "Container"
	LabelVPC            Label = "VPC"
	LabelLoadBalancer   Label = "LoadBalancer"
	LabelDatabase       Label = "Database" // managed DB (RDS, Cloud SQL…), often a crown jewel
	LabelBucket         Label = "Bucket"   // object storage (S3, GCS…), often a crown jewel

	// Code / App
	LabelRepository Label = "Repository"
	LabelImage      Label = "Image"
	LabelPackage    Label = "Package"
	LabelLibrary    Label = "Library"

	// Identity
	LabelUser           Label = "User"
	LabelIAMRole        Label = "IAM_Role"
	LabelServiceAccount Label = "ServiceAccount"

	// Security
	LabelCVE              Label = "CVE"      // known vuln in a dependency (Trivy)
	LabelWeakness         Label = "Weakness" // SAST/code-level weakness, CWE-classified (Semgrep)
	LabelMisconfiguration Label = "Misconfiguration"
	LabelSecret           Label = "Secret"
)

// EdgeType is the type of a directed relationship (E) between two vertices.
type EdgeType string

const (
	// Infrastructure
	EdgeHosts      EdgeType = "HOSTS"
	EdgeConnectsTo EdgeType = "CONNECTS_TO"
	EdgeExposes    EdgeType = "EXPOSES"
	EdgeRoutesTo   EdgeType = "ROUTES_TO"

	// Code / App
	EdgeDependsOn    EdgeType = "DEPENDS_ON"
	EdgeCompiledInto EdgeType = "COMPILED_INTO"
	EdgeBuiltFrom    EdgeType = "BUILT_FROM"

	// Identity
	EdgeAssumes       EdgeType = "ASSUMES"
	EdgeHasPermission EdgeType = "HAS_PERMISSION"

	// Security
	EdgeAffects   EdgeType = "AFFECTS"
	EdgeExploits  EdgeType = "EXPLOITS"
	EdgeMitigates EdgeType = "MITIGATES"
)

// Well-known node property keys that drive analysis. Keeping them as constants
// avoids stringly-typed bugs across collectors and the analyzer.
const (
	// PropInternetExposed (bool) marks a node as a valid traversal *seed*.
	PropInternetExposed = "internet_exposed"
	// PropCrownJewel (bool) marks a node as a valid traversal *target*.
	PropCrownJewel = "crown_jewel"
	// PropSeverity (string) — e.g. CRITICAL/HIGH/MEDIUM/LOW, mainly on findings.
	PropSeverity = "severity"
	// PropCVSS (float64) — base CVSS score when known.
	PropCVSS = "cvss"

	// Pull-request context, attached by collectors when a scan runs in CI on a
	// PR. The action layer uses these to comment on the right pull request.
	PropRepoSlug  = "repo_slug"  // "owner/name"
	PropPRNumber  = "pr_number"  // int
	PropCommitSHA = "commit_sha" // string

	// Runtime context, attached by the Falco collector. A node with an active
	// runtime alert means an attack path through it is being *actively*
	// exercised, not merely theoretical.
	PropRuntimeAlert    = "runtime_alert"    // bool
	PropRuntimeRule     = "runtime_rule"     // string — the Falco rule that fired
	PropRuntimePriority = "runtime_priority" // string — Critical/Warning/…

	// Identity-resolution hints. An asset's image reference lets the resolver
	// link a runtime/cloud container to the image a scanner reported on.
	PropImageRef = "image_ref" // "repo:tag"
	PropARN      = "arn"       // cloud resource ARN
)
