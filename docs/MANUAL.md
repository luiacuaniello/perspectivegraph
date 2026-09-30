# PerspectiveGraph manual

The complete reference: how the engine models risk, how to run it, how to deploy it
and how to operate it. The [README](../README.md) is the short version - what this
is, how to see it working in ninety seconds, and what it does not yet claim.

It is split into pages, one per subject, and published with search at
[docs.a3thinker.it](https://docs.a3thinker.it). The pages here in `docs/manual/` are the
source of that site: a change to either is a change to both.

## Contents

| Page | What it covers |
|---|---|
| [How it works](manual/how-it-works.md) | What an attack path is, the architecture that finds one, and the data model underneath. |
| [Scoring and priority](manual/scoring.md) | How a route gets its probability, how honest that probability is, and what decides which route to fix first. |
| [Accuracy: calibration and validation](manual/accuracy.md) | How the engine grades its own scores against real outcomes, and what it does with the result. |
| [Quick start](manual/quick-start.md) | Running the stack, feeding it sample data, and seeing the first attack path. |
| [Attack paths in the pull request](manual/ci-gate.md) | The merge gate - GitHub Action, CLI and Trivy plugin - and what a developer sees on the pull request. |
| [Sources and integrations](manual/integrations.md) | Agentless connectors, topology discovery, supply-chain provenance, identity resolution and threat intelligence. |
| [Working the findings](manual/working-the-findings.md) | Remediation and detection-as-code, the choke-point optimizer, triage and suppression, and trends over time. |
| [AI assistant and MCP](manual/ai-and-mcp.md) | Asking the attack surface questions in plain language, and letting an agent query it. |
| [Security, authentication and hardening](manual/security.md) | Data hygiene, tenants and SSO, authentication and audit, and hardening the containers and the application. |
| [Deploy to Kubernetes](manual/kubernetes.md) | The Helm chart, a local cluster with the SSO demo, and hardening a real deployment. |
| [Running it: freshness, backup and scaling](manual/running.md) | Keeping the graph fresh, backing it up and restoring it, and scaling the analyzer. |
| [Onboarding runbook](manual/onboarding.md) | Pointing it at your own environment, source by source, until the first path appears. |

## Where each section went

This manual was one page until it passed three thousand lines. Links into that page still
arrive here: every section it had is listed below, with the page it moved to.

| Section | Now in |
|---|---|
| <a name="the-core-idea"></a>The core idea | [How it works](manual/how-it-works.md#the-core-idea) |
| <a name="architecture"></a>Architecture | [How it works](manual/how-it-works.md#architecture) |
| <a name="the-ontology"></a>The ontology | [How it works](manual/how-it-works.md#the-ontology) |
| <a name="risk-scoring"></a>Risk scoring | [Scoring and priority](manual/scoring.md#risk-scoring) |
| <a name="scaling-the-analyzer"></a>&nbsp;&nbsp;Scaling the analyzer | [Scoring and priority](manual/scoring.md#scaling-the-analyzer) |
| <a name="beyond-the-single-best-path"></a>&nbsp;&nbsp;Beyond the single best path | [Scoring and priority](manual/scoring.md#beyond-the-single-best-path) |
| <a name="closing-the-loop-calibration-against-observed-outcomes"></a><a name="the-engines-first-demonstrated-false-positive---found-then-closed"></a><a name="condition-keys-and-why-they-are-not-refutations"></a><a name="resource-scope-what-an-unscoped-question-can-and-cannot-refute"></a>&nbsp;&nbsp;Closing the loop: calibration against observed outcomes | [Accuracy: calibration and validation](manual/accuracy.md#closing-the-loop-calibration-against-observed-outcomes) |
| <a name="event-contract"></a>Event contract | [How it works](manual/how-it-works.md#event-contract) |
| <a name="component-map"></a>Component map | [How it works](manual/how-it-works.md#component-map) |
| <a name="tech-stack"></a>Tech stack | [How it works](manual/how-it-works.md#tech-stack) |
| <a name="quick-start"></a>Quick start | [Quick start](manual/quick-start.md) |
| <a name="the-wedge-attack-paths-in-your-pull-request"></a><a name="the-merge-gate-github-action-cli-and-trivy-plugin"></a>&nbsp;&nbsp;The wedge: attack paths in your pull request | [Attack paths in the pull request](manual/ci-gate.md#the-wedge-attack-paths-in-your-pull-request) |
| <a name="agentless-connectors-pull-dont-wait-for-an-upload"></a>&nbsp;&nbsp;Agentless connectors: pull, don't wait for an upload | [Sources and integrations](manual/integrations.md#agentless-connectors-pull-dont-wait-for-an-upload) |
| <a name="topology-discovery-no-hand-stitched-ids"></a>&nbsp;&nbsp;Topology discovery (no hand-stitched IDs) | [Sources and integrations](manual/integrations.md#topology-discovery-no-hand-stitched-ids) |
| <a name="supply-chain-provenance-sbom-signing-slsa"></a>&nbsp;&nbsp;Supply-chain provenance (SBOM, signing, SLSA) | [Sources and integrations](manual/integrations.md#supply-chain-provenance-sbom-signing-slsa) |
| <a name="closing-the-loop-drift-detection-as-code-siem-export"></a>&nbsp;&nbsp;Closing the loop: drift, detection-as-code, SIEM export | [Working the findings](manual/working-the-findings.md#closing-the-loop-drift-detection-as-code-siem-export) |
| <a name="choke-point-remediation-optimizer"></a>&nbsp;&nbsp;Choke-point remediation optimizer | [Working the findings](manual/working-the-findings.md#choke-point-remediation-optimizer) |
| <a name="ask-your-attack-surface-ai-native---claude-or-huggingface"></a>&nbsp;&nbsp;Ask your attack surface (AI-native - Claude or HuggingFace) | [AI assistant and MCP](manual/ai-and-mcp.md#ask-your-attack-surface-ai-native---claude-or-huggingface) |
| <a name="letting-an-agent-query-it-mcp"></a>&nbsp;&nbsp;Letting an agent query it (MCP) | [AI assistant and MCP](manual/ai-and-mcp.md#letting-an-agent-query-it-mcp) |
| <a name="honest-probabilities-provenance-not-false-precision"></a>&nbsp;&nbsp;Honest probabilities: provenance, not false precision | [Scoring and priority](manual/scoring.md#honest-probabilities-provenance-not-false-precision) |
| <a name="triage-priority-what-to-fix-first-not-500-findings"></a>&nbsp;&nbsp;Triage priority: what to fix first, not 500 findings | [Scoring and priority](manual/scoring.md#triage-priority-what-to-fix-first-not-500-findings) |
| <a name="data-hygiene-a-map-of-the-attack-surface-never-a-vault-of-secrets"></a>&nbsp;&nbsp;Data hygiene: a map of the attack surface, never a vault of secrets | [Security, authentication and hardening](manual/security.md#data-hygiene-a-map-of-the-attack-surface-never-a-vault-of-secrets) |
| <a name="multi-tenant-isolation--sso-login"></a><a name="trying-sso-end-to-end-on-a-laptop-the-bundled-keycloak"></a>&nbsp;&nbsp;Multi-tenant isolation & SSO login | [Security, authentication and hardening](manual/security.md#multi-tenant-isolation--sso-login) |
| <a name="validated-against-reality-precision--recall"></a><a name="calibration-does-the-score-mean-anything-the-demoproduction-gate"></a><a name="discrimination-does-the-order-mean-anything"></a><a name="calibration-diagnostics-and-therefore-what-should-we-build"></a><a name="self-test-without-real-infrastructure"></a><a name="the-on-ramp-to-real-verdicts-the-bas-bridge"></a>&nbsp;&nbsp;Validated against reality (precision & recall) | [Accuracy: calibration and validation](manual/accuracy.md#validated-against-reality-precision--recall) |
| <a name="quantified-risk-what-if--compliance-export"></a>&nbsp;&nbsp;Quantified risk, what-if & compliance export | [Scoring and priority](manual/scoring.md#quantified-risk-what-if--compliance-export) |
| <a name="triage--suppression-close-the-false-positive-loop"></a>&nbsp;&nbsp;Triage & suppression (close the false-positive loop) | [Working the findings](manual/working-the-findings.md#triage--suppression-close-the-false-positive-loop) |
| <a name="trends-mttr--regressions-the-temporal-layer"></a>&nbsp;&nbsp;Trends, MTTR & regressions (the temporal layer) | [Working the findings](manual/working-the-findings.md#trends-mttr--regressions-the-temporal-layer) |
| <a name="identity-resolution-you-can-trust-confidence--explainability"></a>&nbsp;&nbsp;Identity resolution you can trust (confidence + explainability) | [Sources and integrations](manual/integrations.md#identity-resolution-you-can-trust-confidence--explainability) |
| <a name="threat-intel-kev--epss-optional"></a>&nbsp;&nbsp;Threat-intel: KEV + EPSS (optional) | [Sources and integrations](manual/integrations.md#threat-intel-kev--epss-optional) |
| <a name="kev-holdout-a-calibration-dataset-that-builds-itself-optional"></a>&nbsp;&nbsp;KEV holdout: a calibration dataset that builds itself (optional) | [Accuracy: calibration and validation](manual/accuracy.md#kev-holdout-a-calibration-dataset-that-builds-itself-optional) |
| <a name="auth-multi-tenancy--audit-optional-but-do-it-before-production"></a><a name="choosing-between-sso-and-static-tokens"></a>&nbsp;&nbsp;Auth, multi-tenancy & audit (optional, but do it before production) | [Security, authentication and hardening](manual/security.md#auth-multi-tenancy--audit-optional-but-do-it-before-production) |
| <a name="developer-feedback-on-the-pr"></a>&nbsp;&nbsp;Developer feedback on the PR | [Attack paths in the pull request](manual/ci-gate.md#developer-feedback-on-the-pr) |
| <a name="container--compose-hardening"></a>Container & compose hardening | [Security, authentication and hardening](manual/security.md#container--compose-hardening) |
| <a name="application-hardening"></a>&nbsp;&nbsp;Application hardening | [Security, authentication and hardening](manual/security.md#application-hardening) |
| <a name="deploy-to-kubernetes"></a>Deploy to Kubernetes | [Deploy to Kubernetes](manual/kubernetes.md) |
| <a name="local-cluster-docker-desktop--kind--minikube--sso-demo"></a>&nbsp;&nbsp;Local cluster (Docker Desktop / kind / minikube) + SSO demo | [Deploy to Kubernetes](manual/kubernetes.md#local-cluster-docker-desktop--kind--minikube--sso-demo) |
| <a name="hardening-a-real-deployment-beyond-a-trusted-cluster"></a><a name="transport-security-tls--data-in-transit"></a>&nbsp;&nbsp;Hardening a real deployment (beyond a trusted cluster) | [Deploy to Kubernetes](manual/kubernetes.md#hardening-a-real-deployment-beyond-a-trusted-cluster) |
| <a name="operating-it-freshness-backup--dr"></a>Operating it: freshness, backup & DR | [Running it: freshness, backup and scaling](manual/running.md#operating-it-freshness-backup--dr) |
| <a name="scaling-the-analyzer-1"></a>&nbsp;&nbsp;Scaling the analyzer | [Running it: freshness, backup and scaling](manual/running.md#scaling-the-analyzer) |
| <a name="onboarding-runbook"></a>Onboarding runbook | [Onboarding runbook](manual/onboarding.md) |
| <a name="0-prerequisites"></a><a name="authentication"></a>&nbsp;&nbsp;0. Prerequisites | [Onboarding runbook](manual/onboarding.md#0-prerequisites) |
| <a name="1-the-order-that-builds-a-correct-graph"></a>&nbsp;&nbsp;1. The order that builds a correct graph | [Onboarding runbook](manual/onboarding.md#1-the-order-that-builds-a-correct-graph) |
| <a name="2-per-source-snippets"></a><a name="trivy-dependency--image-cves"></a><a name="ci-build-provenance-the-link-that-connects-code-findings"></a><a name="supply-chain-provenance-cosign--slsa--sbom"></a><a name="semgrep-sast-weaknesses--secrets"></a><a name="cloud-custodian-cloud-inventory--iam"></a><a name="falco-runtime-confirmation"></a><a name="kubernetes-topology-auto-discovered-exposure"></a><a name="cloud-network-reachability-auto-discovered"></a><a name="iam-privilege-escalation-graph-auto-discovered"></a><a name="sso--idp-federation-okta--cloud---the-modern-front-door"></a>&nbsp;&nbsp;2. Per-source snippets | [Onboarding runbook](manual/onboarding.md#2-per-source-snippets) |
| <a name="3-the-two-markers-that-make-paths-appear"></a>&nbsp;&nbsp;3. The two markers that make paths appear | [Onboarding runbook](manual/onboarding.md#3-the-two-markers-that-make-paths-appear) |
| <a name="4-identifier-correlation-the-make-or-break-detail"></a>&nbsp;&nbsp;4. Identifier correlation (the make-or-break detail) | [Onboarding runbook](manual/onboarding.md#4-identifier-correlation-the-make-or-break-detail) |
| <a name="5-network-topology---now-auto-discovered"></a>&nbsp;&nbsp;5. Network topology - now auto-discovered | [Onboarding runbook](manual/onboarding.md#5-network-topology---now-auto-discovered) |
| <a name="6-verify-a-path-formed"></a><a name="quantify-risk-simulate-fixes-export-for-compliance"></a><a name="close-the-loop-verify-a-fix-then-own-it"></a><a name="validate-against-reality-red-team--bas"></a><a name="triage-a-path-youve-decided-about"></a>&nbsp;&nbsp;6. Verify a path formed | [Onboarding runbook](manual/onboarding.md#6-verify-a-path-formed) |
| <a name="7-troubleshooting---i-see-no-attack-paths"></a>&nbsp;&nbsp;7. Troubleshooting - "I see no attack paths" | [Onboarding runbook](manual/onboarding.md#7-troubleshooting---i-see-no-attack-paths) |
| <a name="8-run-it-continuously"></a><a name="keep-it-fresh-so-it-cant-drift-into-fiction"></a><a name="manage-on-trends-not-snapshots"></a>&nbsp;&nbsp;8. Run it continuously | [Onboarding runbook](manual/onboarding.md#8-run-it-continuously) |
