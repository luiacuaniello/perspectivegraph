# AI assistant and MCP

*Part of the [PerspectiveGraph manual](../MANUAL.md).* Asking the attack surface questions in plain language, and letting an agent query it.

## Ask your attack surface (AI-native - Claude or HuggingFace)

Set `ANTHROPIC_API_KEY` and the dashboard grows an **AI assistant** powered by
Claude (`claude-opus-5`):

- **Natural-language Q&A** - *"which internet-exposed path reaches customer PII
  fastest?"* - answered from the live graph.
- **Executive summary** - a board-ready brief of the current posture: the headline
  risk, what's actively exploited, the top fix.
- **Explain (AI)** - a plain-English walk-through of any single path and the one
  most effective fix, on the path detail.

Every answer is **grounded** in the tenant's actual attack paths - the model is
handed a compact, capped context, so it summarizes your data rather than inventing
assets. The transport is a **hand-rolled** call to Anthropic's `/v1/messages` (no
SDK, no new dependencies - the engine stays pure-Go and auditable).

**Who may ask, and how often.** Each answer is a paid call to the model provider, so
the `/ai/*` endpoints need a signed-in caller: on a read-only public instance
(`API_ANONYMOUS_ROLE=viewer`) anonymous visitors get 403, and `aiEnabled` answers
`false` for them so the dashboard does not offer the buttons. They also have a rate limit
of their own, `AI_RATE_PER_MIN` (default 10 per client per minute), on top of
`API_RATE_RPS`. With auth off entirely - the local demo - everyone may ask.

**Prefer a free model?** If you don't set `ANTHROPIC_API_KEY` but set `HF_TOKEN`
(a free [HuggingFace](https://huggingface.co/settings/tokens) access token), the
same features run against HuggingFace's OpenAI-compatible Inference router instead.
Pick the chat model with `HF_MODEL` (default `meta-llama/Llama-3.1-8B-Instruct`),
and point `HF_BASE_URL` at any OpenAI-compatible endpoint (Together, Groq, a local
Ollama, …) to use those. Anthropic takes precedence when both are set; everything
else (grounding, audit, the dashboard UI) is identical.

**Every answer names the model that wrote it.** The `/ai/*` responses carry `provider`
and `model` alongside `answer`, and the dashboard prints them under the text. This is
not decoration: prose reads with the same authority whichever backend produced it, and
these two are not interchangeable — an 8B model writing a board-level risk brief is a
different thing from Opus writing one, and only the reader can decide what that is worth
to them. Withholding it would be the same false confidence the engine refuses to produce
for a score it cannot back up. For the same reason the model is told, in every system
prompt, that the probabilities in its context are the engine's own estimates rather than
measurements — the caveat the MCP tool descriptions already give an agent, said here to
the layer that writes for humans.

Because the graph *is* the org's attack map, sending a compacted view of it to an
external model is a deliberate opt-in: the feature is off until you set the key,
and **every AI call is audited** (`ai.query` / `ai.summary` / `ai.explain`) into
the same tamper-evident log as the rest of the read path.

## Letting an agent query it (MCP)

A language model is weak at exactly what this engine is good at: it cannot enumerate thousands
of edges reliably, it does not run Dijkstra, and asked for "the attack paths in my account" it
will produce plausible routes that do not exist. So the engine speaks
[MCP](https://modelcontextprotocol.io) - an agent calls it and reasons over answers it could not
have invented.

```bash
make mcp    # or: perspectivegraph mcp --api http://localhost:8080
```

```json
{"mcpServers": {"perspectivegraph": {
  "command": "perspectivegraph",
  "args": ["mcp", "--api", "http://localhost:8080"]}}}
```

No engine running? `perspectivegraph mcp --api https://demo.a3thinker.it` answers every tool -
`simulate_fix` included - from the public demo's sample data, with no credential.

Eight tools: `get_posture`, `list_attack_paths`, `explain_attack_path`, `routes_to_target`,
`list_fixes`, **`simulate_fix`**, `search_assets`, `get_score_trust`. The one worth the
integration is `simulate_fix` - it re-runs the whole simulation with the given edges cut and
reports what actually changes, settling "would this help" with a deterministic counterfactual
instead of an argument.

The surface is **read-only**: nothing suppresses a path, opens a PR or records a verdict,
because an agent that can silently accept a risk is a liability rather than a feature. Every
tool declares that on the wire (`readOnlyHint`), so a host can decide what to run unattended
without taking this paragraph's word for it - and a test fails if a tool is ever added without
that decision. The descriptions also tell the model the scores are expert estimates, and to call
`get_score_trust` before quoting one as a probability. Every tool is run against the real engine
in the test suite, not only a stub, so a query naming a field the schema lacks fails the build
instead of an agent's call. `search_assets` asks the engine whether full-text search is on:
without OpenSearch an agent is told so, instead of receiving an empty result that reads as "no
asset by that name".

The server is in the official [MCP Registry](https://registry.modelcontextprotocol.io) as
`io.github.luiacuaniello/perspectivegraph`, published from every stable release, and on
[Glama](https://glama.ai/mcp/servers/luiacuaniello/perspectivegraph), which builds it, inspects
the tools it exposes and grades their definitions - a grade of the MCP surface, not of the
engine's scores.
