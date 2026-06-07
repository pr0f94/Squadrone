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
- **Specialist agent coverage** across auth, auth-flow, injection, file ops, SSRF/deserialization, XSS, and logic flaws
- **Source-grounded triage** against exploitability and Wordfence/Patchstack scope rules
- **Strict quality gates** that reject admin-only, self-only, config-dependent, and low-impact findings before they waste review time
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
Triage      accepted 1 · rejected 1 · merged 0
Verify      findings 1
Report      reports 2
```

The SQLite index is created automatically at `db/squadrone.sqlite` on first use.

## What it does

1. Pulls plugin source from `plugins.svn.wordpress.org`.
2. Maps attack surface: reachable entry points, nonce/capability checks, and risky sinks.
3. Runs specialist LLM agents with on-demand `grep_plugin`, `glob_plugin`, and `read_plugin_file` tools instead of dumping the full plugin into context.
4. Self-verifies hypotheses to drop fabricated sinks and missed-guard claims.
5. Builds a focus-area map for AJAX/REST, forms, files, auth, SQL, payment logic, and rendering paths.
6. Triages survivors against exploitability and bounty-scope rules.
7. Applies strict quality gates: evidence completeness, WordPress false-positive rules, and derived severity.
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
- `subversion`
- LLM access through LiteLLM-compatible providers

On macOS:

```sh
brew install ripgrep subversion
```

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

# Use the OpenAI/ChatGPT pipeline
squadrone scan contact-form-7 --budget 5.00 --config pipelines/openai.yaml

# Skip sandbox verification and queue accepted hypotheses for manual review
squadrone scan contact-form-7 --no-verify

# Disable strict quality gates for exploratory research
squadrone scan contact-form-7 --no-strict-quality

# Require a majority vote from three independent Critic passes
squadrone scan contact-form-7 --triage-votes 3

# Run exploit-chain synthesis between hypotheses before triage
squadrone scan contact-form-7 --chain

# Scan multiple plugins from a file, one slug per line
squadrone scan-batch plugins.txt

# Scan multiple plugins in parallel
squadrone scan-batch plugins.txt --concurrency 3

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
- `plugins/<slug>/runs/<run_id>/findings.jsonl`
- `plugins/<slug>/runs/<run_id>/trace.jsonl`
- `plugins/<slug>/runs/<run_id>/report_<finding_id>_<program>.md`

When `--no-verify` is used, triage-accepted hypotheses are first graded by the quality gate, then written to the manual review queue instead of `findings.jsonl`; no submission reports are generated.

## Quality gates

Squadrone's default pipelines enable strict quality controls. These are deterministic checks inspired by verifier/grader harnesses:

- **Finding grader before manual queue** rejects candidates without realistic submit-worthy impact.
- **WordPress false-positive rules** reject admin-only, self-XSS, own-resource-only, config-dependent, cosmetic, open redirect, and low-impact CSRF cases.
- **Evidence-first schema** annotates each survivor with attacker role, source, sink, affected file/function, guard discussion, impact statement, and bounty routing.
- **Severity recomputation** derives an internal CVSS-style score and OWASP 2021 category instead of trusting model-written severity.
- **Report grader** blocks confirmed findings from becoming polished reports if the evidence or impact does not meet the submission bar.
- **Focused review fanout** writes `focus_areas.json` and feeds the attack-surface map into specialist review.
- **Verifier voting** is available with `--triage-votes N`; use `3` or `5` when quality matters more than runtime.
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
