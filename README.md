<p align="center">
  <img src="assets/squadrone_badge_transparent.png" alt="Squadrone" width="260" />
</p>

<h1 align="center">Squadrone</h1>

<p align="center">
  <b>Run multi-agent vulnerability research against WordPress plugins.</b><br/>
  Source-grounded triage, sandbox verification, and private disclosure drafts.
</p>

Most vulnerability scanners stop at patterns. Squadrone runs a full research pipeline over WordPress plugins: it pulls plugin source, maps reachable entry points, asks specialist agents to form hypotheses, verifies survivors in a Docker WordPress sandbox, deduplicates against known vulnerability databases, and writes disclosure-ready report drafts.

What you get:

- **One-command plugin scans** from a WordPress.org plugin slug
- **Specialist agent coverage** across auth, auth-flow, object authorization, state changes, payment logic, injection, file ops, SSRF/deserialization, stored-to-admin paths, XSS, and logic flaws
- **Source-grounded triage** against exploitability and Wordfence/Patchstack scope rules
- **Balanced quality gates** that reject clear false positives while preserving borderline evidence or impact for manual review
- **Sandbox verification** with an isolated WordPress install and iterative PoC attempts
- **Known-vulnerability deduplication** against Wordfence Intelligence and WPScan when API keys are available
- **Private report drafts** for novel findings, with no auto-submit path

## ⚡ Quickstart

Install the prerequisites below first, and make sure Docker Desktop is running
before starting a scan.

```sh
git clone https://github.com/pr0f94/Squadrone.git squadrone
cd squadrone
python3.12 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
cp .env.example .env
$EDITOR .env
set -a; . ./.env; set +a
.venv/bin/squadrone --help
.venv/bin/squadrone scan hello-dolly
```

The default pipeline uses Anthropic models, so set `ANTHROPIC_API_KEY` in `.env`
before running the scan. To use ChatGPT subscription OAuth instead, run:

```sh
.venv/bin/squadrone scan hello-dolly --config pipelines/openai.yaml
```

Each scan writes artifacts under `plugins/<slug>/runs/<run_id>/`.

```text
Intake      version 1.7.2 · files 42 · lines 4,812
Recon       entry points 8 · sinks 3
Hypothesis  count 2
Triage      accepted 1 · rejected 1 · merged 0 · manual review 0
Verify      findings 1
Report      reports 2
```

The SQLite index is created automatically at `db/squadrone.sqlite` on first use.
SQLite connections use WAL mode and a busy timeout so batch scans can share the
run index and LLM cache without most transient lock failures.

## What it does

1. Pulls plugin source from `plugins.svn.wordpress.org`, falling back to the WordPress.org plugin ZIP if `svn` is not installed.
2. Maps attack surface: reachable entry points, nonce/capability checks, risky sinks, plugin type, sensitive objects, custom roles/capabilities, and high-risk workflows.
3. Runs role-aware and workflow-aware specialist LLM agents with on-demand `grep_plugin`, `glob_plugin`, and `read_plugin_file` tools instead of dumping the full plugin into context.
4. Self-verifies hypotheses to drop only definitely ungrounded claims such as fabricated sinks, impossible bug classes, or explicit missed guards.
5. Builds a focus-area map for AJAX/REST, forms, files, auth, SQL, payment logic, and rendering paths.
6. Triages survivors against exploitability and bounty-scope rules, including an adversarial rejection pass when multiple triage votes are used; split votes are routed to manual review.
7. Applies balanced quality gates: evidence completeness, WordPress false-positive rules, derived severity, and manual-review routing for borderline cases.
8. Builds a one-shot Docker WordPress sandbox for accepted hypotheses.
9. Iteratively runs LLM-authored Python PoCs against the sandbox.
10. Deduplicates confirmed findings against Wordfence Intelligence and WPScan when keys are configured.
11. Runs a report-quality gate before writing disclosure drafts.
12. Writes private report drafts per finding and program.
13. Records run metadata and findings in SQLite for later review.

The system **never auto-submits** anything. It produces files. You decide what to disclose, where, and when.

## Why use agents instead of static-only scanning?

You should not pick only one approach. Static scanning is fast and broad; agentic review is slower but can reason across WordPress idioms, exploit preconditions, scope rules, and PoC feedback.

### Where Squadrone helps

| | Squadrone | Static grep / rules |
|---|:---:|:---:|
| WordPress-specific authorization reasoning | ✓ | partial |
| Cross-file hypothesis formation | ✓ | partial |
| Scope-aware bounty triage | ✓ | ✗ |
| Sandbox PoC verification | ✓ | ✗ |
| Report draft generation | ✓ | ✗ |
| Known-vuln deduplication | ✓ | partial |
| Cheap broad pre-filtering | partial | ✓ |
| Deterministic repeated output | partial | ✓ |

The intended workflow is conservative: use static tools and human review alongside Squadrone, then manually validate anything you plan to report.

## Prerequisites

- Python 3.12+
- Docker Desktop running before verification
- `ripgrep`
- `subversion` optional, but recommended for WordPress.org source checkout; Squadrone falls back to plugin ZIP downloads when `svn` is unavailable
- LLM access through LiteLLM-compatible providers

On macOS:

```sh
brew install ripgrep subversion
```

If you do not install `subversion`, scans can still run through the ZIP
fallback, but historical source layouts may be less precise for some plugins.

## 🛠️ Install

```sh
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

The editable install exposes:

```sh
.venv/bin/squadrone --help
```

## ⚙️ Configure

Copy the example environment file:

```sh
cp .env.example .env
```

Set whichever keys match your pipeline and dedup needs:

| Variable | Required for | Notes |
|---|---|---|
| `ANTHROPIC_API_KEY` | Claude models | Used by `pipelines/default.yaml` |
| `OPENAI_API_KEY` | OpenAI API models | Not needed for `chatgpt/` subscription models |
| `WORDFENCE_API_KEY` | dedup stage | Wordfence Intelligence v3 production feed |
| `WPSCAN_API_KEY` | dedup stage | wpscan.com plugin DB |
| `LITELLM_LOG` | optional logging | Example: `WARNING` |

If a vuln-DB key is missing, dedup logs a warning and skips that source. The scan does not fail solely because a dedup key is absent.

Pipeline YAML files in `pipelines/` control models, budget ceiling, sandbox shape, hypothesis limits, and developer-consult caps.

`pipelines/openai.yaml` uses LiteLLM's `chatgpt/` provider for ChatGPT subscription access. On first use, LiteLLM starts an OAuth device-code flow; complete the browser login prompt and Squadrone will use the authenticated ChatGPT session. This path does not require `OPENAI_API_KEY`.

## 🚀 Use

```sh
# Scan one plugin with the default pipeline
squadrone scan hello-dolly

# Scan with a higher budget
squadrone scan contact-form-7 --budget 5.00

# Scan a specific historical plugin release
squadrone scan contact-form-7 --version 5.3.1

# Use the OpenAI/ChatGPT pipeline
squadrone scan contact-form-7 --budget 5.00 --config pipelines/openai.yaml

# Show detailed stage, agent, sandbox, and LLM logs
squadrone scan contact-form-7 --verbose

# Skip sandbox verification and queue accepted hypotheses for manual review
squadrone scan contact-form-7 --no-verify

# Disable bounty-scope filtering when you only care whether a bug is technically valid
squadrone scan contact-form-7 --ignore-scope

# Disable strict quality gates for exploratory research
squadrone scan contact-form-7 --no-strict-quality

# Require a majority vote from three independent Critic passes
squadrone scan contact-form-7 --triage-votes 3

# Run exploit-chain synthesis between hypotheses before triage
squadrone scan contact-form-7 --chain

# Enable the larger cross-file stored-XSS specialist
squadrone scan contact-form-7 --cross-file-taint

# Compare the scanned version against a prior WordPress.org release
squadrone scan contact-form-7 --version 5.3.2 --diff 5.3.1

# Scan multiple plugins from a file, one slug per line
squadrone scan-batch plugins.txt

# Scan multiple plugins in parallel
squadrone scan-batch plugins.txt --concurrency 3

# Batch flags mirror the scan quality/scope controls
squadrone scan-batch plugins.txt --concurrency 3 --triage-votes 3 --no-verify

# Resume an existing run
squadrone scan contact-form-7 --resume <run_id>

# Force re-run from a specific stage
squadrone scan contact-form-7 --resume <run_id> --from verify

# Inspect run history and findings
squadrone runs list
squadrone findings show <finding-id>

# Interactively review findings
squadrone review <run-id>

# Record a disclosure you submitted manually
squadrone disclose <finding-id> --to wordfence --notes "Sent via Wordfence portal"

# Run the benchmark harness
squadrone benchmark benchmarks/corpus.json --split train --budget 5.00
```

Output by default:

- `plugins/<slug>/runs/<run_id>/intake.json`
- `plugins/<slug>/runs/<run_id>/recon.json`
- `plugins/<slug>/runs/<run_id>/hypotheses.jsonl`
- `plugins/<slug>/runs/<run_id>/focus_areas.json`
- `plugins/<slug>/runs/<run_id>/chains.json` when `--chain` is used
- `plugins/<slug>/runs/<run_id>/chain_diagnostics.json` when `--chain` is used
- `plugins/<slug>/runs/<run_id>/triaged.jsonl`
- `plugins/<slug>/runs/<run_id>/quality_gate_triage.json`
- `plugins/<slug>/runs/<run_id>/manual_review_queued.json` when triage or quality gates queue manual review
- `plugins/<slug>/runs/<run_id>/findings.jsonl`
- `plugins/<slug>/runs/<run_id>/findings_corrupt.jsonl` if malformed finding rows are quarantined during resume
- `plugins/<slug>/runs/<run_id>/schema_invalid_<agent>.json` if an agent returns invalid structured output after repair
- `plugins/<slug>/runs/<run_id>/decision_ledger.jsonl`
- `plugins/<slug>/runs/<run_id>/trace.jsonl`
- `plugins/<slug>/runs/<run_id>/report_<finding_id>_<program>.md`

When `--no-verify` is used, triage-accepted hypotheses are first graded by the quality gate, then written to the manual review queue instead of `findings.jsonl`; no submission reports are generated.

When triage voting or the quality gate cannot make a clean automatic decision, the hypothesis is preserved in the manual review queue. The per-run `decision_ledger.jsonl` records the exact stage, action, result, reason, and artifact path for each keep, reject, manual-review, verification, dedup, and report decision.

Run artifacts that affect resume are written atomically where possible. If a
crash leaves malformed rows in `findings.jsonl`, Squadrone preserves readable
findings, writes the bad rows to `findings_corrupt.jsonl`, and records the
recovery in `decision_ledger.jsonl`.

## Quality gates

Squadrone's default pipelines enable strict quality controls. These are deterministic checks inspired by verifier/grader harnesses:

- **Finding grader before verification** accepts strong candidates, hard-rejects clear false positives, and routes borderline evidence or impact to manual review.
- **WordPress false-positive rules** reject admin-only, self-XSS, own-resource-only, cosmetic, open redirect, and low-impact CSRF cases; borderline submit-worthiness can be preserved for manual review.
- **Evidence-first schema** annotates each survivor with attacker role, source, sink, affected file/function, guard discussion, impact statement, and bounty routing.
- **Severity recomputation** derives an internal CVSS-style score and OWASP 2021 category instead of trusting model-written severity.
- **Report grader** blocks confirmed findings from becoming polished reports if the evidence or impact does not meet the submission bar.
- **Focused review fanout** writes `focus_areas.json` and feeds the attack-surface map into specialist review.
- **V2 methodology** is the default: the surveyor maps plugin type, sensitive objects, roles, and workflows; specialists review object authorization, state changes, payment logic, and stored-to-admin paths alongside classic vulnerability classes.
- **Verifier voting** is available with `--triage-votes N`; use `3` or `5` when quality matters more than runtime. In multi-vote mode, majority-accepted findings continue, zero-accept findings reject, and split votes go to manual review.
- **Exploit-chain synthesis** is available with `--chain`; it enriches hypotheses with `chains_with`, `chain_impact`, and `chain_severity_bump`, and writes `chain_diagnostics.json` so skipped, failed, and empty chain passes are distinguishable.

Use `--no-strict-quality` for exploratory scans where you want more raw hypotheses.

## 🔍 Triage

```sh
# List runs
squadrone runs list

# Show one finding
squadrone findings show <finding-id>

# Review a completed run interactively
squadrone review <run-id>
```

A confirmed finding typically has:

```json
{
  "id": "f-...",
  "poc_status": "confirmed",
  "dedup_status": "novel",
  "report_paths": [
    "plugins/<slug>/runs/<run_id>/report_f-..._wordfence.md",
    "plugins/<slug>/runs/<run_id>/report_f-..._patchstack.md"
  ]
}
```

Treat generated reports as drafts. Confirm the bug manually, reproduce the PoC, check source-side sanitization and authorization carefully, then disclose privately through the appropriate channel.

## 🧪 Tests

```sh
.venv/bin/pytest tests/unit/ -q
.venv/bin/ruff check src/
.venv/bin/mypy src/
```

## Architecture

- **stages/** — async pipeline functions: intake, recon, hypothesis, triage, verify, dedup, report
- **agents/** — LLM-backed agents and the runtime tool-call loop
- **services/** — LiteLLM gateway, budget tracker, SVN client, vuln-DB clients, Docker sandbox manager, WP-CLI wrapper
- **schemas/** — Pydantic artifact models
- **prompts/** — markdown system prompts for every agent
- **poc_templates/** — Jinja2 PoC skeletons and Python helpers
- **orchestrator.py** — stage orchestration, SQLite persistence, budget handling

For a deeper design walkthrough, see `DESIGN.md`.

## Responsible disclosure

This tool is for authorised security research and responsible disclosure only.

Expected workflow:

1. Scan a plugin you are allowed to test.
2. Review confirmed findings manually.
3. Reproduce and validate impact outside the generated draft.
4. Disclose privately via Patchstack mVDP, Wordfence Vulnerability Disclosure, WPScan, or the plugin author.
5. Wait for a fix before any public write-up.
6. Use `squadrone disclose` only to record your own disclosure status.

Do not point Squadrone at infrastructure you do not own or have explicit written permission to test.
