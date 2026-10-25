<p align="center">
  <img src="assets/squadrone_badge_transparent.png" alt="Squadrone" width="260" />
</p>

<h1 align="center">Squadrone</h1>

<p align="center">
  <b>Automated WordPress plugin vulnerability research.</b><br/>
  Deterministic coverage, source review, sandbox verification, and private disclosure drafts.
</p>

Squadrone scans a WordPress.org plugin from source to a reproducible finding. It
combines static inventory with LLM source review, rejects candidates without a
concrete confidentiality, integrity, or availability impact, verifies survivors
in a local Docker WordPress sandbox, checks known vulnerability databases, and
writes private Wordfence or Patchstack report drafts.

It never submits findings automatically.

## Quickstart

Install the prerequisites, make sure Docker and Compose are running, then run:

```sh
git clone https://github.com/pr0f94/Squadrone.git squadrone
cd squadrone
python3.12 -m venv .venv
.venv/bin/python -m pip install "pip==26.2.1"
.venv/bin/python -m pip install -c requirements/constraints.txt -e ".[dev]"
.venv/bin/playwright install chromium
cp .env.example .env
$EDITOR .env
.venv/bin/squadrone scan hello-dolly
```

The default pipeline routes every LLM role to
`chatgpt/gpt-daybreak-blue-latest` through ChatGPT subscription OAuth in
LiteLLM. It uses `medium` reasoning by default. The authenticated ChatGPT
account must be provisioned for that model; no OpenAI API key is needed:

```sh
.venv/bin/squadrone scan hello-dolly --config pipelines/chatgpt.yaml
```

The first `chatgpt/` request may start an OAuth device-code flow. This route does
not need `OPENAI_API_KEY` or any other model API key. The `.env` step is optional
for this default route; credential loading is explained under
[Configuration](#configuration). Do not source `.env` as a shell script.

Alternatively, use the OpenCode Go / Go Plus pipeline:

```sh
export OPENCODE_GO_API_KEY='your-go-key'
.venv/bin/squadrone scan hello-dolly --config pipelines/opencode-go.yaml
```

This pipeline uses GLM-5.3 (`max` reasoning) for the surveyor, DeepSeek V4.1
Flash (`high` reasoning) for all four specialists, hypothesis verifier, critic,
developer/setup, developer follow-up and PoC author, and Qwen3.8 Max for reports.
It does not need `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`. The existing Daybreak
pipeline and the default CLI configuration are unchanged.

If Go rejects a model with “requires Global regions,” review the workspace's
Privacy settings in OpenCode Console. Region selection is an account/privacy
decision; Squadrone does not change it automatically. This can block DeepSeek
even when other Go models work with the same key.

Both shipped pipelines have a `$10` estimated ceiling for each plugin run. Before
dispatch, Squadrone blocks a call whose conservative reservation would cross
that ceiling. A response that has already completed is retained and accounted
for. With ChatGPT or Go subscription access, these dollar values are internal
token-price estimates, not the remaining subscription allowance or an invoice.

## Research Process

1. **Intake** downloads the latest release or a pinned historical version,
   rejects closed latest-version targets, and records the source metadata.
2. **Coverage and threat mapping** inventory production PHP, JavaScript,
   TypeScript, templates, built assets, entry points, storage operations, risky
   sinks, roles, capabilities, workflows, and call paths.
3. **Specialist source review** examines four areas by default:
   authorization/workflows, injection/files, XSS lifecycle, and authentication.
   Review is split into resumable source-local batches, and every completed
   review disposition requires cited source. Incomplete work receives up to
   four progressively narrowed attempts; any remaining gap is stored explicitly
   as `unreviewed` rather than silently treated as covered.
4. **Source validation** checks exact sink quotes against source. The verifier
   and critic assess source contradictions, reachability, controls, attacker
   role, security boundary, and concrete confidentiality, integrity, or
   availability impact; deterministic gates check required evidence and
   role/version consistency.
5. **Triage** ranks source-valid candidates and selects the configured number
   for sandbox verification. Default scans also apply configured finding-level
   Wordfence and Patchstack class, role, and impact rules. Asset eligibility,
   such as install count, vendor exclusions, and program enrollment, must be
   checked separately. Valid candidates below the cap are retained as deferred.
6. **Sandbox verification** provisions legitimate prerequisites in an isolated
   WordPress/MariaDB stack, executes a generated Python PoC with a structured
   attack/control oracle, restores the database and complete WordPress
   filesystem, and repeats the exact PoC from clean state. Both executions must
   pass before Squadrone creates a finding.
7. **Deduplication and reporting** query Wordfence Intelligence and, when
   `WPSCAN_API_KEY` is set, WPScan. The report stage then calculates CVSS v3.1
   from confirmed evidence and creates private drafts for non-duplicate findings
   that pass report-evidence and program-scope checks. Verification-only runs
   skip these stages and may retain findings without assigned CVSS scores.

See the [process flow diagram](docs/diagrams/process-flow.svg) for mode-specific
stops, review outcomes, retries, and clean-state confirmation.

Evidence checks, negative controls, and clean-state confirmation are enforced by
the pipeline. Pipeline YAML configures operational choices such as models,
budget, candidate limits, and sandbox settings.

An **accepted triage candidate is not a confirmed vulnerability**. Matching
source anchors and consistent metadata do not prove WordPress save/filter/render
behavior, runtime reachability, or that a feature exceeds its intended authority.
Developer consultations are model advice, not independently inspected core source.
Unresolved or conflicting prerequisites can require manual review; runtime proof
and operator review are still needed before disclosure.

Verification begins only after Squadrone removes WordPress from its temporary
bootstrap network. At runtime WordPress and MariaDB have only an internal Docker
network, while a trusted fixed-target ingress proxies the sandbox URL from a
host port bound to `127.0.0.1`. Startup inspects the network flags, exact
container memberships, published-port bindings, and Docker's persisted primary
network mode and fails closed if the sealed topology differs. The internal
network remains the persistent restart target while the temporary bootstrap
network owns only the installation-time default route.

HTTP SSRF proofs do not reopen general target egress. When requested, the
ingress receives one unexposed listener for the current parent-owned oracle
port; it denies every path except the fixed `/_squadrone/ssrf/` capability
prefix. Squadrone validates the proxy configuration and probes it from
WordPress. Rotation removes the old relay before releasing its parent port, and
teardown removes the relay before stopping the oracle.

The Docker target keeps this server-side boundary for every PoC. Host-side PoCs
outside the trace-bound HTTP path use a compatibility runner with a filtered
environment, however, and do not yet have strict socket isolation. Browser and
inbound-callback proofs therefore require operator review when external network
access is prohibited.

## Prerequisites

- Python 3.12.14 (recorded in `.python-version`)
- Docker Engine 28.0 or later with Docker Compose 2.33.1 or later (current
  Docker Desktop on macOS); the sealed sandbox uses `priority` and
  `gw_priority` to separate its durable restart network from bootstrap egress
- `ripgrep`
- Playwright Chromium (installed by the Quickstart command)
- `subversion` optional; pinned historical releases use SVN when available and
  fall back to the official versioned ZIP if SVN or the tag is unavailable
- Access to the models selected in the pipeline YAML

On macOS:

```sh
brew install ripgrep subversion
```

Install the project:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install "pip==26.2.1"
.venv/bin/python -m pip install -c requirements/constraints.txt -e ".[dev]"
.venv/bin/playwright install chromium
```

`pyproject.toml` pins every direct and development dependency. The constraints
file additionally pins the complete resolved dependency graph; use it for all
supported installs so transitive packages cannot drift independently.

## Configuration

```sh
cp .env.example .env
$EDITOR .env
```

The CLI reads process environment variables. The pinned LiteLLM dependency can
also load a discovered `.env` as data in its default `LITELLM_MODE=DEV`; existing
exported values normally take precedence. With `LITELLM_MODE=PRODUCTION`, that
implicit loader is disabled, so export/inject the required variables before
starting Squadrone. Squadrone does not provide a separate dotenv loader. Never use
`source .env` or `. ./.env`: those execute file contents as shell code. Keep real
keys out of shell history and shared logs; the export examples use placeholders.

| Variable | Used for | Required |
|---|---|---|
| `ANTHROPIC_API_KEY` | Custom pipeline configurations using Anthropic models | Only for those custom configurations |
| `OPENAI_API_KEY` | OpenAI API models | Not for `chatgpt/` OAuth models |
| `OPENCODE_GO_API_KEY` | OpenCode Go / Go Plus models | For `pipelines/opencode-go.yaml` |
| `WORDFENCE_API_KEY` | Optional authenticated dedup feed access | No |
| `WPSCAN_API_KEY` | WPScan dedup lookup | No |
| `LITELLM_LOG` | LiteLLM logging level | No |
| `LITELLM_MODE` | LiteLLM development/production environment behavior | No; defaults to `DEV` |
| `LITELLM_LOCAL_MODEL_COST_MAP` | Use LiteLLM's bundled cost map without its metadata download | No; set `True` for offline tests |

Pipeline YAML controls model routing, reasoning effort, cost ceiling, candidate
cap, PoC iterations, sandbox images/timeouts, persistent sandbox reuse, failure
state dumps, and optional screenshots. Most users only need to change models or
budget.

`llm.reasoning_effort` is inherited by every agent role. A value under
`reasoning.<role>` overrides it only for that role; the four focused reviewers
all use the `specialists` role. Supported override names are `critic`,
`developer`, `developer_followup`, `surveyor`, `poc_author`, `specialists`,
`reporter`, and `hypothesis_verifier`.

### OpenCode Go model profiles

`pipelines/opencode-go.yaml` defines named `model_profiles`, referenced as
`profile/<name>` in the role mapping. Each profile specifies the upstream model,
HTTPS API base, API format, environment-variable name (never a literal key),
generation defaults, supported reasoning efforts, history policy, output limit
and per-million-token price estimates. Legacy LiteLLM model strings still work.
Role/global generation settings override profile defaults; unsupported controls
fail explicitly rather than being silently discarded. Do not copy Daybreak's
global `medium` reasoning into GLM: GLM supports `low`, `high` and `max`.
Qwen's Messages route is not given Claude-specific thinking controls.

| Profile | Roles | API format | Reasoning | Output allowance |
|---|---|---|---|---|
| `go-glm` / GLM-5.3 | Surveyor | OpenAI-compatible Chat | `max` | Cap 32,768 |
| `go-deepseek` / DeepSeek V4.1 Flash | Specialists, hypothesis verifier, critic, developer/setup, developer follow-up, PoC author | OpenAI-compatible Chat | `high` | Floor 16,384; cap 32,768 |
| `go-qwen` / Qwen3.8 Max | Reporter | Anthropic-compatible Messages | No Claude-specific controls | Cap 16,384 |

DeepSeek's `output_budget_floor: 16384` raises short helper calls' initial shared
reasoning/answer allowance to at least 16,384 tokens; it does not require a long
answer or guarantee one.
DeepSeek requests remain capped at `max_output_tokens: 32768`. An incomplete
one-shot generation gets at most one regeneration at that ceiling when a larger
allowance is available, with both attempts accounted against the run budget.
Refusals and filtered responses do not trigger expansion. Setup JSON may also
need its existing one-time shape repair, so one setup operation can use up to
four separately budgeted generations. Tool-loop output is not automatically
expanded: an incomplete response fails the loop explicitly. Empty or truncated
output is never accepted as advice or executable setup, even if its partial JSON
parses; legitimate tool-only turns are allowed. An exhausted consultation is
reported to its caller as unavailable and non-authoritative, not as an empty
successful answer or expert agreement. Legacy model strings do not gain output
allowance expansion.

The gateway uses the [documented Go endpoints and client headers](https://opencode.ai/v2/docs/console/go/)
with Bearer authentication, Squadrone's own user agent and a stable conversation
ID. Concurrent reviews and developer consultations receive distinct IDs;
continuations, retries and JSON repair retain their conversation ID. Keys are
resolved only at dispatch and are not included in traces, response-cache keys or
model provenance. For Chat-compatible profiles, nonempty `OPENAI_CUSTOM_HEADERS`,
`OPENAI_ORG_ID`, `OPENAI_PROJECT_ID` or `OPENAI_ORGANIZATION` cause a clear error:
unset them for the Go process to prevent unrelated SDK headers leaking to Go.
`OPENAI_API_KEY` and `ANTHROPIC_API_KEY` may remain set; they are not used by Go.
The shipped Go profiles preserve complete reasoning/tool history rather than
silently dropping earlier turns; context overflow fails explicitly at a configured
input estimate limit or at the provider's actual token limit.
Custom profiles may explicitly select the legacy `history_policy: trim` instead.
DeepSeek also enables `empty_tool_reasoning`: omitted/null reasoning slots on
assistant tool turns are serialized as an explicit empty string when required
by the upstream API. Actual reasoning is preserved unchanged. This wire-only
compatibility option does not invalidate completed model-stage checkpoints;
effective normalized messages still determine response-cache keys, and request
traces record the option separately.

The `$10` run ceiling is an internal usage estimate, **not** your remaining Go
allowance, a subscription charge or an invoice. Profile prices were checked on
2026-10-21; DeepSeek uses peak rates conservatively, so off-peak spend can be
overestimated. The gateway does not switch providers/models when quota runs out.
Go Console's optional Extra usage setting can independently allow paid overflow;
check that setting and actual allowances in your account.

Resumes record effective model routes/settings, prompt hashes and methodology
revisions. A change archives the first affected stage and its downstream outputs
under `model_archive/<id>/` before recomputing them; compatible earlier stages and
batch checkpoints remain reusable. A legacy run
without model provenance cannot be migrated to a profile pipeline in place: start
a new run. The old artifacts remain available.

Specialists receive the inspected version from intake. Triage can retain
unresolved attacker roles, conflicting role prerequisites, and unsupported
historical-version claims for manual review without rewriting the original
claim; other disqualifying quality failures can still require rejection. These
checks do not prove core routing, payload survival or runtime exploitability.

Offline adapter tests do not prove your account's entitlement or live service
availability. Complete a small live tool-call/structured-output check for each
model before relying on this pipeline for research.

Focused discovery can limit source review to one or more areas; omit this field
to retain all four reviewers in their fixed order:

```yaml
hypothesis_review_areas:
  - injection_files
hypothesis_review_item_types:
  - deserialization
```

Valid areas are `authorization_workflows`, `injection_files`, `xss_lifecycle`,
and `authentication`. The optional item-type list matches deterministic
`CoverageItem.type` values exactly; omit it to review every item type.

## Usage

```sh
# Latest release, default pipeline
.venv/bin/squadrone scan contact-form-7

# Per-run cumulative budget ceiling override
.venv/bin/squadrone scan contact-form-7 --budget 5

# Historical release, primarily for benchmark/regression work
.venv/bin/squadrone scan contact-form-7 --version 5.3.1

# ChatGPT subscription pipeline with detailed logs
.venv/bin/squadrone scan contact-form-7 \
  --config pipelines/chatgpt.yaml --budget 5 --verbose

# Newline-delimited batch, sequential by default
.venv/bin/squadrone scan-batch plugins.txt

# Sequential verification-only batch (no deduplication or reporting)
.venv/bin/squadrone scan-batch plugins.txt --concurrency 1 --verify-only

# Sequential triage-only batch (no sandbox verification, deduplication, or reporting)
.venv/bin/squadrone scan-batch plugins.txt --concurrency 1 --triage-only

# Parallel batch
.venv/bin/squadrone scan-batch plugins.txt --concurrency 3

# Higher-budget research batch ($100 independently per plugin)
.venv/bin/squadrone scan-batch plugins.txt --budget 100 \
  --config pipelines/chatgpt.yaml --verbose

# Resume after the latest completed stage; reuse the original pipeline and mode
.venv/bin/squadrone scan contact-form-7 --resume <run_id>

# Resume an interrupted Go triage-only run, retaining compatible completed batches
.venv/bin/squadrone scan contact-form-7 --resume <run_id> \
  --config pipelines/opencode-go.yaml --triage-only --budget 2

# Resume and force a specific stage onward
.venv/bin/squadrone scan contact-form-7 --resume <run_id> --from verify

# Stop after source-valid triage, before sandbox verification
.venv/bin/squadrone scan contact-form-7 --triage-only

# Verify source-valid candidates without deduplication or reporting
.venv/bin/squadrone scan contact-form-7 --verify-only
```

Use `.venv/bin/squadrone scan --help` or
`.venv/bin/squadrone scan-batch --help` for the complete option reference.
`--triage-only` and `--verify-only` are mutually exclusive:

- `--triage-only` disables disclosure-program scope filtering and stops after
  technical triage and manual-queue handoff, before Docker verification,
  vulnerability-database lookup, or reporting. Manual scaffolds may appear under
  `verifications/`; they are not evidence that a sandbox or PoC ran.
- `--verify-only` includes out-of-program-scope candidates in technical triage,
  runs verification, and skips vulnerability-database lookup and reporting.

A triage-only run can be resumed with either mode. Verify-only resume reuses its
technical-triage artifact; a normal resume reruns triage with disclosure scope
enabled before continuing through verification, deduplication, and reporting.

`--resume` does not restore the original pipeline path, mode flags, or budget
override. Pass the same `--config` and `--triage-only`/`--verify-only` mode when
continuing the same workflow. Omitting `--config` selects the Daybreak default
and can invalidate a Go run's outputs. Omitting a mode flag requests the full
disclosure workflow. Within an unfinished hypothesis stage, compatible completed
review batches are reused and only unfinished/incompatible batches are repeated.
There is no durable checkpoint inside an individual tool loop, although matching
LLM responses can be reused from the semantic cache. `--from` forces stage
re-entry; it does not bypass that cache or automatically discard valid batch
checkpoints.

Resume restores the prior `cost_calls.tsv` before making another model call.
Earlier and resumed calls, including work repeated with `--from`, share one
cumulative ceiling; `--budget` replaces that total ceiling rather than adding
new allowance. A ceiling below already-recorded spend is rejected. Batch
ceilings are independent per plugin.

Ctrl-C retains normal cancellation semantics. Every committed run row is
checkpointed with terminal status `interrupted`, a finish timestamp, cumulative
cost reports, a pipeline ledger entry, and any crash-safe partial findings. In a
parallel batch, cancellation propagates to active peers; queued plugins may not
start, and interrupted runs are resumed individually by run ID.

## Artifacts

Each run is stored under `plugins/<slug>/runs/<run_id>/`. Important files are:

- `intake.json`: target version and source metadata
- `recon.json`: canonical attack-surface and threat map
- `coverage.json`: production files, deterministic review items, and reviewer dispositions
- `hypotheses_<review_area>.jsonl`: each reviewer's candidates
- `coverage_<review_area>.json`: each reviewer's evidence-backed item decisions
- `review_batches/<review_area>/`: bounded reviewer checkpoints used for resume
- `hypotheses.jsonl`: source-verifier survivors
- `triaged.json`: accepted, rejected, merged, deferred, and manual dispositions
- `quality_gate_triage.json`: deterministic source/impact decisions
- `model_provenance.json`: stage model/route identities, prompt hashes, and methodology revisions
- `model_archive/<id>/`: recoverable incompatible stage outputs preserved on resume
- `verifications/<hypothesis_id>/`: generated PoCs, manual handoff scaffolds, and optional diagnostics
- `verify_complete.json`: verification completion marker used for compatible resume
- `manual_review_queued.json`: manual-queue handoff fingerprints used to prevent duplicate enqueueing
- `findings.jsonl`: clean-state confirmed findings and structured observations
- `decision_ledger.jsonl`: every keep, reject, defer, verify, dedup, and report decision
- `trace.jsonl`: agent and tool activity
- `cost_calls.tsv`: cumulative per-model-call token and estimated-cost records
- `cost_per_stage.tsv`: cumulative per-stage cost and cache-use summary
- `report_<finding_id>_<program>.md`: private report drafts

Artifacts used for resume are written atomically where possible. Malformed
finding rows are quarantined to `findings_corrupt.jsonl` rather than silently
discarded.

Once a sandbox context is active, teardown removes any active SSRF relay before
releasing its parent listener, attempts `docker compose down -v`, removes the
temporary bootstrap network, and removes temporary work and snapshot
directories after normal completion, failure, and ordinary cancellation.
Cleanup is best effort. An interrupt during optional persistent-sandbox setup,
a repeated interrupt, or a hard process kill may require manual Docker cleanup.
Persistent sandbox reuse remains confined to one verification run.

## Manual Review

Triage or verification may use the manual queue for a source-grounded candidate
whose actor, prerequisites, transport, or other required evidence automation
cannot establish. Unresolved/mixed attacker roles, role/prerequisite conflicts,
and version claims beyond the inspected release can be retained unchanged for
manual review rather than silently repaired. Other quality failures may be
rejected; scope-ineligible or lower-ranked candidates may be deferred. Neither
manual status nor acceptance establishes exploitability or intended authority.

```sh
.venv/bin/squadrone manual list
.venv/bin/squadrone manual remove <row-or-hypothesis-id>
.venv/bin/squadrone manual clear
```

## Findings And Disclosure

```sh
.venv/bin/squadrone runs list
.venv/bin/squadrone findings show <finding-id>
.venv/bin/squadrone review <run-id>
.venv/bin/squadrone disclose <finding-id> --to wordfence --notes "Submitted privately"
```

Generated reports remain drafts. Reproduce the final request and impact before
submitting through the selected program.
`disclose` only records a submission you made separately; it does not send a
report or contact a program.

## Benchmark

The benchmark scans both the vulnerable and fixed version for every corpus
entry. It reports hypothesis recall separately from clean-PoC verified recall,
fixed-version target false positives, paired verified precision, and cost per
confirmed target. A hypothesis alone is never counted as a confirmed finding.

```sh
.venv/bin/squadrone benchmark benchmarks/corpus.json --split train --budget 5
```

## Seeded Regression

Seeded regressions test whether a previously source-grounded hypothesis still
survives source verification and technical triage, then reproduces with both an
attack run and a clean-state confirmation. This is intentionally separate from
the paired benchmark above: it tests downstream integrity without treating
rediscovery variance as a verifier failure.

The manifest is a versioned JSON object with a `cases` array. Each case provides
`case_id`, `cve_id`, `plugin_slug`, `version`, `mode`, one complete canonical
`Hypothesis` under `hypothesis`, and an `expected` object. A `confirm` expectation
requires `attribution`, `attacker_role`, `minimum_impact`, and one or more
`allowed_oracles`. The attribution object records the exact final
`hypothesis_id`, `bug_class`, `root_cause_cwe`, `file`, `line`, `sink`, and
`sink_code`; it is separate from the seeded hypothesis so a source-anchor repair
can itself be regression tested, including a corrected dangerous expression on
the same source line. A `policy_reject` expectation instead lists the deterministic
`rejection_rules` and may also provide exact attribution. `source_tree_sha256`
is optional and pins the downloaded source tree when present.

The budget is required and applies independently to every selected case. Cases
run sequentially, so at most one verification sandbox is active. The harness
does not run vulnerability-database feeds, deduplication, or reporting. Plugin
source and run artifacts remain under ignored `plugins/`; suite results remain
under ignored `benchmarks/results/`.

```sh
env -u WORDFENCE_API_KEY -u WPSCAN_API_KEY \
  .venv/bin/squadrone regression benchmarks/regressions.json \
  --config pipelines/chatgpt.yaml --budget 100

# Run one or more named cases from the same manifest
.venv/bin/squadrone regression benchmarks/regressions.json --budget 100 \
  --case duplicator-cve-2020-11738 --case getwid-cve-2023-1895
```

## Tests

```sh
LITELLM_LOCAL_MODEL_COST_MAP=True .venv/bin/pytest -q
.venv/bin/ruff check --select E9,F63,F7,F82 src tests benchmarks
```

The Ruff command checks critical syntax and name failures across the current
tree. Use broader Ruff checks on the files changed by a patch rather than
assuming every optional rule is part of the current baseline.

Adapter tests exercise real serialization against mocked HTTP responses; they
do not prove live account entitlement, model accuracy, or full sandbox/report
behavior. The real Docker network regression is opt-in:

```sh
SQUADRONE_RUN_DOCKER_ENGINE_TESTS=1 \
  LITELLM_LOCAL_MODEL_COST_MAP=True \
  .venv/bin/pytest tests/test_docker_network_restart_integration.py -q
```

That test requires a running compatible Docker Engine and a locally available
probe image (`wordpress:latest` by default, or `SQUADRONE_DOCKER_ENGINE_TEST_IMAGE`);
the test never pulls images. Some offline tests also require local loopback
sockets or macOS sandbox permissions.

## Architecture

![Squadrone architecture](docs/diagrams/architecture.svg)

- `src/squadrone/stages/`: intake through report pipeline
- `src/squadrone/agents/`: source reviewers and LLM runtime
- `src/squadrone/agents/transport/litellm_transport.py`: tool loops, full assistant history, structured-output repair, and completeness guards
- `src/squadrone/services/`: coverage, scope, quality, LLM, Docker, and dedup services
- `src/squadrone/services/llm.py`: shared LiteLLM gateway, semantic response cache, bounded one-shot recovery, and budget accounting
- `src/squadrone/services/model_profiles.py`: explicit API routes, validated generation controls, credential lookup, and request-envelope normalization
- `src/squadrone/services/llm_context.py`: independent conversation scopes and parent/child context
- `src/squadrone/services/model_provenance.py`: stage identities, prompt/policy tracking, and recoverable resume invalidation
- `src/squadrone/docker/`: packaged Compose and WordPress runtime assets
- `src/squadrone/schemas/`: Pydantic artifact contracts
- `src/squadrone/prompts/`: agent and current program instructions
- `src/squadrone/poc_templates/`: PoC skeletons and evidence helpers
- `benchmarks/`: paired benchmark corpus and seeded historical-CVE regressions

See [DESIGN.md](DESIGN.md) for the architecture, design-level walkthrough, and
known limits.

## Responsible Disclosure

Use Squadrone only for authorized security research. Its PoCs target the local
Docker sandbox and are instructed not to call external systems. Keep findings
private, verify them independently, use one responsible disclosure channel, and
wait for remediation before publishing details. Disclose AI assistance wherever
the receiving program requires it.
