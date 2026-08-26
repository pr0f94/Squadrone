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

Install the prerequisites, start Docker Desktop, then run:

```sh
git clone https://github.com/pr0f94/Squadrone.git squadrone
cd squadrone
python3.12 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/playwright install chromium
cp .env.example .env
$EDITOR .env
set -a; . ./.env; set +a
.venv/bin/squadrone scan hello-dolly
```

The default pipeline uses Anthropic models and needs `ANTHROPIC_API_KEY`. To use
ChatGPT subscription OAuth through LiteLLM instead:

```sh
.venv/bin/squadrone scan hello-dolly --config pipelines/openai.yaml
```

The first `chatgpt/` request may start an OAuth device-code flow. This route does
not need `OPENAI_API_KEY`.

## Research Process

1. **Intake** downloads the requested release, rejects closed latest-version
   targets, and records an immutable run artifact.
2. **Deterministic coverage** inventories shipped PHP, JavaScript, TypeScript,
   templates, built assets, external callbacks, storage operations, and risky
   sinks. Tests/docs are excluded; bundled dependencies remain inspectable.
3. **Threat mapping** enriches that inventory with plugin objects, roles,
   capabilities, workflows, dynamic registrations, and call paths.
4. **Four source reviewers** own authorization/workflows, injection/files,
   XSS lifecycle, and authentication. They work through bounded source-local
   batches with unrestricted source tools. Every disposition must cite the
   assigned line from a tool read, and every candidate must link its hypothesis.
   Callback workflows receive both authorization and XSS review so reflected
   rendering remains covered without treating every output call as a separate task.
   Minified assets retain match columns, so reading only the start of a very long
   physical line cannot satisfy evidence for a sink later on that line.
5. **Source verification and critic review** reject hallucinated citations,
   missed guards, unreachable paths, unrealistic roles, and claims without a
   concrete security boundary and CIA outcome.
6. **Scope and ranking** route technically valid candidates by current
   Wordfence/Patchstack vulnerability, role, and impact rules, rank by attacker
   role and impact, then apply the sandbox candidate cap. Plugin selection is
   responsible for asset-level install-count/vendor eligibility. Lower-ranked
   valid candidates are marked deferred, not falsely rejected.
7. **Sandbox verification** configures legitimate prerequisites, executes a
   generated Python PoC, validates a class-specific structured attack/control
   oracle, restores the full database and `wp-content`, and reruns the exact PoC.
   A finding requires both executions to pass. HTTP 200, reflection, a blind
   callback, or printed `SUCCESS` text is not proof.
8. **Confirmed scoring and deduplication** calculate CVSS v3.1 only from the
   confirmed attacker role and CIA observation, then compare the result with
   Wordfence Intelligence and WPScan.
9. **Reporting** drafts one private report per eligible disclosure program.
   Confirmed findings that fail the evidence or current program rules do not get
   polished into submission drafts.

This process is mandatory. Pipeline YAML no longer contains switches that turn
off source grounding, coverage, quality checks, controls, or confirmation.

## Prerequisites

- Python 3.12+
- Docker Desktop
- `ripgrep`
- Playwright Chromium (installed by the Quickstart command)
- `subversion` optional; plugin ZIP download is the automatic fallback
- Access to the models selected in the pipeline YAML

On macOS:

```sh
brew install ripgrep subversion
```

Install the project:

```sh
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/playwright install chromium
```

## Configuration

```sh
cp .env.example .env
```

| Variable | Used for | Required |
|---|---|---|
| `ANTHROPIC_API_KEY` | Models in `pipelines/default.yaml` | For the default pipeline |
| `OPENAI_API_KEY` | OpenAI API models | Not for `chatgpt/` OAuth models |
| `WORDFENCE_API_KEY` | Optional authenticated dedup feed access | No |
| `WPSCAN_API_KEY` | WPScan dedup lookup | No |
| `LITELLM_LOG` | LiteLLM logging level | No |

Pipeline YAML controls model routing, reasoning effort, cost ceiling, candidate
cap, PoC iterations, sandbox images/timeouts, persistent sandbox reuse, failure
state dumps, and optional screenshots. Most users only need to change models or
budget.

## Usage

```sh
# Latest release, default pipeline
.venv/bin/squadrone scan contact-form-7

# Per-scan budget override
.venv/bin/squadrone scan contact-form-7 --budget 5

# Historical release, primarily for benchmark/regression work
.venv/bin/squadrone scan contact-form-7 --version 5.3.1

# ChatGPT subscription pipeline with detailed logs
.venv/bin/squadrone scan contact-form-7 \
  --config pipelines/openai.yaml --budget 5 --verbose

# Newline-delimited batch, sequential by default
.venv/bin/squadrone scan-batch plugins.txt

# Parallel batch
.venv/bin/squadrone scan-batch plugins.txt --concurrency 3

# Higher-budget research batch
.venv/bin/squadrone scan-batch plugins.txt --budget 100 \
  --config pipelines/openai-research.yaml --verbose

# Resume after the latest completed stage
.venv/bin/squadrone scan contact-form-7 --resume <run_id>

# Resume and force a specific stage onward
.venv/bin/squadrone scan contact-form-7 --resume <run_id> --from verify
```

`scan` supports `--config`, `--budget`, `--version`, `--resume`, `--from`, and
`--verbose`. `scan-batch` supports `--concurrency`, `--config`, `--budget`,
`--version`, and `--verbose`.

There is intentionally no `--no-verify`, `--chain`, `--cross-file-taint`, or
`--triage-votes` mode. Cross-file review and verification are part of the fixed
methodology.

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
- `verifications/<hypothesis_id>/`: generated PoCs and optional diagnostics
- `findings.jsonl`: clean-state confirmed findings and structured observations
- `decision_ledger.jsonl`: every keep, reject, defer, verify, dedup, and report decision
- `trace.jsonl`: agent and tool activity
- `report_<finding_id>_<program>.md`: private report drafts

Artifacts used for resume are written atomically where possible. Malformed
finding rows are quarantined to `findings_corrupt.jsonl` rather than silently
discarded.

## Manual Review

The critic may use the manual queue only for a source-proven candidate with one
narrow runtime fact automation cannot establish. Quality-gate failures and
lower-ranked candidates are rejected or deferred explicitly instead of being
hidden in that queue.

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

## Benchmark

The benchmark scans both the vulnerable and fixed version for every corpus
entry. It reports hypothesis recall separately from clean-PoC verified recall,
fixed-version target false positives, paired verified precision, and cost per
confirmed target. A hypothesis alone is never counted as a confirmed finding.

```sh
.venv/bin/squadrone benchmark benchmarks/corpus.json --split train --budget 5
```

## Tests

```sh
.venv/bin/pytest -q
.venv/bin/ruff check src tests benchmarks
.venv/bin/mypy src
```

## Architecture

- `src/squadrone/stages/`: intake through report pipeline
- `src/squadrone/agents/`: source reviewers and LLM runtime
- `src/squadrone/services/`: coverage, scope, quality, LLM, Docker, and dedup services
- `src/squadrone/schemas/`: Pydantic artifact contracts
- `src/squadrone/prompts/`: agent and current program instructions
- `src/squadrone/poc_templates/`: PoC skeletons and evidence helpers
- `benchmarks/`: paired vulnerable/fixed regression corpus

See `DESIGN.md` for the design-level walkthrough.

## Responsible Disclosure

Use Squadrone only for authorized security research. Its PoCs target the local
Docker sandbox and are instructed not to call external systems. Keep findings
private, verify them independently, use one responsible disclosure channel, and
wait for remediation before publishing details. Disclose AI assistance wherever
the receiving program requires it.
