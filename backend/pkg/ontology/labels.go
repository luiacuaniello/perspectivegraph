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
	LabelUser             Label = "User"
	LabelIAMRole          Label = "IAM_Role"
	LabelServiceAccount   Label = "ServiceAccount"
	LabelIdentityProvider Label = "IdentityProvider" // SSO/IdP (Okta, Entra, …) — the federated front door

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
	// EdgeCanEscalateTo is an IAM privilege-escalation primitive: the source
	// principal can, through its permissions, gain the target's privileges.
	EdgeCanEscalateTo EdgeType = "CAN_ESCALATE_TO"
	// EdgeAuthenticates links an IdP to an identity it can authenticate — the SSO
	// front door: compromise/phish the identity at the IdP and you inherit its
	// federated cloud roles.
	EdgeAuthenticates EdgeType = "AUTHENTICATES"
	// EdgeEscapesTo is a container/host-boundary escape: a workload with a
	// host-breaking setting (privileged, hostPath, hostPID/Network/IPC) can break
	// out of its container and take over the node — and from a node, the cluster
	// (MITRE ATT&CK T1611). Distinct from CAN_ESCALATE_TO (an IAM/RBAC primitive).
	EdgeEscapesTo EdgeType = "ESCAPES_TO"

	// Security
	EdgeAffects   EdgeType = "AFFECTS"
	EdgeExploits  EdgeType = "EXPLOITS"
	EdgeMitigates EdgeType = "MITIGATES"
)

// validLabels / validEdgeTypes are the closed sets of the ontology vocabulary.
// The AGE store interpolates labels and edge types directly into Cypher (they
// cannot be bound as parameters), so it must validate them against these sets
// first — a defense-in-depth allowlist so a future bug that lets external data
// reach a label/edge type can never become Cypher injection.
var validLabels = map[Label]bool{
	LabelVirtualMachine: true, LabelContainer: true, LabelVPC: true,
	LabelLoadBalancer: true, LabelDatabase: true, LabelBucket: true,
	LabelRepository: true, LabelImage: true, LabelPackage: true, LabelLibrary: true,
	LabelUser: true, LabelIAMRole: true, LabelServiceAccount: true, LabelIdentityProvider: true,
	LabelCVE: true, LabelWeakness: true, LabelMisconfiguration: true, LabelSecret: true,
}

var validEdgeTypes = map[EdgeType]bool{
	EdgeHosts: true, EdgeConnectsTo: true, EdgeExposes: true, EdgeRoutesTo: true,
	EdgeDependsOn: true, EdgeCompiledInto: true, EdgeBuiltFrom: true,
	EdgeAssumes: true, EdgeHasPermission: true, EdgeCanEscalateTo: true, EdgeAuthenticates: true,
	EdgeEscapesTo: true,
	EdgeAffects:   true, EdgeExploits: true, EdgeMitigates: true,
}

// IsValidLabel reports whether l is part of the ontology vocabulary.
func IsValidLabel(l Label) bool { return validLabels[l] }

// IsValidEdgeType reports whether t is part of the ontology vocabulary.
func IsValidEdgeType(t EdgeType) bool { return validEdgeTypes[t] }

// Well-known node property keys that drive analysis. Keeping them as constants
// avoids stringly-typed bugs across collectors and the analyzer.
const (
	// PropInternetExposed (bool) marks a node as a valid traversal *seed*.
	PropInternetExposed = "internet_exposed"
	// PropCrownJewel (bool) marks a node as a valid traversal *target*.
	PropCrownJewel = "crown_jewel"
	// PropCrownJewelBasis (string) records WHY a node is a crown jewel — "tagged"
	// (an explicit owner tag), "classified:<source>:<kind>" (an authoritative
	// data-classification finding, e.g. Macie/DLP), or "inferred:<signal>" (the
	// engine guessed from a strong signal, e.g. a PII-named data store). So reliance
	// on perfect hand-tagging is reduced *and* the reason is always auditable.
	PropCrownJewelBasis = "crown_jewel_basis"
	// PropClassification (string) is an asset's data classification from a real
	// classifier (Macie/DLP/tag policy): pii | phi | pci | financial | secret | … —
	// authoritative evidence that the asset holds something worth stealing.
	PropClassification = "classification"
	// PropSecretsScrubbed (bool) marks a node whose property values had a
	// secret-looking token redacted at ingest (see internal/scrub). The finding is
	// kept; the credential value is not — so reading the attack map never hands out
	// a live secret. Its presence is the audit trail that scrubbing fired.
	PropSecretsScrubbed = "secrets_scrubbed"
	// PropSeverity (string) — e.g. CRITICAL/HIGH/MEDIUM/LOW, mainly on findings.
	PropSeverity = "severity"
	// PropCVSS (float64) — base CVSS score when known.
	PropCVSS = "cvss"

	// Threat-intel enrichment on CVE nodes (see internal/threatintel).
	// PropKEV (bool) — the CVE is in CISA's Known Exploited Vulnerabilities
	// catalog: confirmed exploited in the wild, not merely theoretical.
	PropKEV = "kev"
	// PropEPSS (float64) — FIRST EPSS probability of exploitation in the next
	// 30 days, [0,1]. PropEPSSPercentile is its percentile rank, [0,1].
	PropEPSS           = "epss"
	PropEPSSPercentile = "epss_percentile"

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

	// Identity-resolution provenance: when the normalizer *infers* a join (e.g.
	// stitches a container to the image a scanner reported on), it records HOW and
	// HOW SURE, so an analyst can see — and distrust — a heuristic correlation
	// instead of a hard identity. A low confidence is a "verify this link" signal.
	PropResolutionMethod     = "resolution_method"     // string — digest | tag | name
	PropResolutionConfidence = "resolution_confidence" // float64 [0,1]
	PropResolutionAlias      = "resolution_alias"      // string — the raw ref that was matched

	// PropLastSeen (int64, unix seconds) is stamped on every node and edge each
	// time it is observed, so the staleness pruner can remove assets that fell out
	// of the source feeds (a deleted pod, a torn-down SG) instead of letting them
	// linger and produce *phantom* attack paths. Items that predate this stamp (no
	// last_seen) are never pruned — grandfathered until they are next observed.
	PropLastSeen = "last_seen"

	// Supply-chain provenance & trust, attached by the supplychain collector from
	// cosign / SLSA / SBOM data. An *assessed* image carries PropSigned (true or
	// false); its absence means "never assessed", which is distinct from "unsigned".
	// An internet-reachable unsigned image is a tampering vector — the build could
	// be swapped — so it's a first-class supply-chain risk, not just metadata.
	PropSigned            = "signed"             // bool — cosign signature verified
	PropSLSALevel         = "slsa_level"         // int [0..4] — SLSA build provenance level
	PropProvenanceBuilder = "provenance_builder" // string — attested builder identity
	PropSBOMComponents    = "sbom_components"    // int — components recorded from the SBOM

	// PropWeightBasis (string) records WHERE an edge's exploit probability came
	// from, so the score can declare its own trustworthiness instead of presenting
	// a guessed number as fact: kev | epss | runtime (evidence) vs cvss | severity
	// | heuristic (estimate). Stamped by the threat-intel reweighter for kev/epss;
	// the analyzer infers the rest. See analyzer.weightBasisOf.
	PropWeightBasis = "weight_basis"
)
