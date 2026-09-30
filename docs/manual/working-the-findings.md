# Working the findings

*Part of the [PerspectiveGraph manual](../MANUAL.md).* Remediation and detection-as-code, the choke-point optimizer, triage and suppression, and trends over time.

## Closing the loop: drift, detection-as-code, SIEM export

Analysis without action is a report. PerspectiveGraph pushes its findings into
the daily workflow:

- **Drift alerting** - the analyzer diffs each pass and fires a webhook
  (Slack-format or generic JSON for SOAR) when a **new** attack path appears:
  *":rotating_light: 3 new critical attack paths: internet → … → cluster-admin (52%)"*.
  The sticky feature - you hear about a regression the moment a deploy introduces it.
- **Detection-as-code** - every path generates **Falco + Sigma** rules that
  *detect* exploitation of its exposed workload (scoped by container/namespace,
  referencing the path's CVE and sensitive asset). Remediation cuts the path;
  detection watches it - closing the offense→defense loop.
- **SIEM enrichment export** - `GET /export/ndjson` streams one record per asset
  on a critical path (`on_critical_path`, `max_path_score`, `kev`,
  `runtime_confirmed`, …) in the NDJSON shape Splunk/Elastic/Sentinel ingest, so
  your SIEM can prioritize alerts about hosts that sit on a reachable path.
- **Verified remediation** - every generated fix records the exact edge it cuts,
  so the API *proves* it works: applying it is simulated (what-if, on the same
  trials before and after) and the plan shows **"✓ verified · removes N paths ·
  −X%"** instead of trusting the generator. Verified means the cut removes a path
  or lowers the expected number of sensitive assets compromised; a scaffold that
  protects nothing is flagged **"⚠ unverified"**.
- **Owned tickets** - raise a tracked, **owned** remediation ticket for a path
  (one open ticket per path, with status), recorded locally and optionally
  dispatched to an external tracker (`TICKET_WEBHOOK_URL` → Jira/GitHub/SOAR;
  dry-run when unset). The dashboard shows **"Ticketed · owner"** and closes it
  when done - the finding→fix→done loop, with accountability.

```bash
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/… make run-backend   # drift → Slack
curl -s $API/export/ndjson | head                                       # SIEM enrichment feed
```

## Choke-point remediation optimizer

Most critical paths share a handful of edges, so the question that matters isn't
"what are the 50 paths" but "what is the *smallest set of fixes* that removes the
most risk". The **Remediation** view answers it: a weighted greedy set-cover over
the generated artifacts ranks them so the top entries are the few fixes that
neutralize the most critical-path risk - e.g. *"5 fixes eliminate 92% of
critical-path risk"* - each with the ready-to-apply Terraform/NetworkPolicy and
an honest residual for paths needing manual review. The artifact catalog covers
the full ontology, including the newer edge types: an **IAM privilege-escalation**
path (`CAN_ESCALATE_TO`) yields a deny-the-primitive policy, and a **cloud
lateral-movement** edge (`CONNECTS_TO`) yields a security-group segmentation rule.

## Triage & suppression (close the false-positive loop)

A finding nobody can dismiss is a finding nobody trusts. PerspectiveGraph has a
first-class **triage loop**: from any attack path, record a decision that takes
it off the active board - **accept-risk**, **false-positive**,
**mitigating-control** or **duplicate** - with an **accountable owner**, an
optional note, and an optional **expiry** after which the path automatically
returns to the board (so *"accept for 30 days"* can't silently become *"accept
forever"*). The overview then headlines **active** paths and shows how many are
suppressed; the list dims and labels them and hides them behind a *Show
suppressed* toggle. The suppression board is the audit of the tool's *own*
findings - who decided what, and why.

```bash
# Suppress a path (admin when auth is on); expires automatically after ttlDays.
curl -s -X POST "$API/suppressions" -H 'Content-Type: application/json' -d '{
  "pathId": "ap-1a2b-3c4d", "reason": "mitigating-control",
  "owner": "secops@acme", "note": "WAF rule blocks this", "ttlDays": 30 }'
curl -s "$API/suppressions"                       # the triage board (incl. expired)
curl -s -X DELETE "$API/suppressions/ap-1a2b-3c4d"  # un-suppress
```

Set `SUPPRESSIONS_PATH` to persist decisions across restarts (else they live in
memory only). Each `attackPath` in GraphQL now carries `suppressed` and a
`suppression { reason owner note createdAt expiresAt }`.

## Trends, MTTR & regressions (the temporal layer)

A scanner tells you what's wrong *now*; security is managed on *trends*. The
analyzer folds every pass into a history, so PerspectiveGraph answers the
questions a point-in-time tool can't:

- **"How long has this path been open?"** Every attack path carries a
  `firstSeen`/`openForSeconds`, surfaced as an **"open 5d"** badge - persistence,
  not just existence, is what you triage on.
- **MTTR.** When a path stops appearing (fixed, or its asset went away) it's
  marked resolved; *resolved − first_seen* is its time-to-remediate, rolled up
  into an **MTTR** card - the accountability metric management actually asks for.
- **Regressions.** A path that resolved and came back is flagged **"⟳ reopened
  N×"** - the deploy-introduced-it-again signal, distinct from a brand-new path.
- **Exposure trend.** A sampled (critical-paths, account-compromise %) series
  drives a **sparkline** on the overview: a rising line is a regression to chase,
  a falling one is progress you can show a board.

It's all in GraphQL (`history { trend mttrSeconds openPaths resolvedPaths
oldestOpenSince }`, plus `firstSeen`/`openForSeconds`/`reopens` per path); set
`HISTORY_PATH` so "open for 5 days" survives a restart (else it's in-memory).
