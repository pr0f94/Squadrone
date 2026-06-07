# Squadrone — Multi-Agent WordPress Vulnerability Research Tool

---

## Project Overview

A multi-agent security research system that accepts a WordPress plugin slug, works autonomously
to discover vulnerabilities, and produces verified PoC exploits for human review. The researcher
manually validates all findings before any disclosure.

**Target ecosystem:** WordPress plugins (wordpress.org directory)
**Goal:** Find novel vulnerabilities, obtain CVEs, build CV through responsible disclosure
**Disclosure targets:** Wordfence Vulnerability Disclosure, Patchstack mVDP, WPScan DB, or the plugin author. The reporter agent generates separate `report_<finding_id>_<program>.md` files per applicable program; the researcher submits manually through each program's web form.

---

## Technology Stack

| Concern | Decision |
|---------|----------|
| Language | Python 3.12+ |
| Async style | `asyncio` throughout, `httpx` for all async HTTP |
| LLM access | `litellm` — supports Anthropic API, OpenAI API, ChatGPT-subscription OAuth, Gemini, Bedrock, Vertex, and other LiteLLM providers |
| PoC script HTTP client | `requests` (sync, simpler for generated scripts) |
| Database | SQLite via `aiosqlite` |
| Validation | `pydantic` v2 for all artifact schemas |
| CLI | `typer` |
| Containerisation | Docker + `docker-compose` via Python `aiodocker` |
| PHP static analysis | `ripgrep` for initial pattern survey; agents drive their own exploration via `grep_plugin` / `read_plugin_file` tools |
| Config | YAML pipeline config loaded at startup |

### Dependencies (pyproject.toml)

```toml
[project]
name = "squadrone"
version = "0.1.0"
requires-python = ">=3.12"

dependencies = [
    "litellm>=1.40.0",
    "httpx>=0.27.0",
    "requests>=2.32.0",
    "aiosqlite>=0.20.0",
    "pydantic>=2.7.0",
    "typer>=0.12.0",
    "aiodocker>=0.22.0",
    "pyyaml>=6.0.1",
    "jinja2>=3.1.0",
    "rich>=13.7.0",
    "tenacity>=8.3.0",
]

[project.optional-dependencies]
dev = ["pytest", "pytest-asyncio", "pytest-httpx", "ruff", "mypy"]
```

---

## Model Assignments

Model strings are defined in `pipelines/default.yaml` (Anthropic API keys) or `pipelines/openai.yaml` (ChatGPT-subscription OAuth) and are overridable per run.

**Recommended assignments by role (Anthropic — `pipelines/default.yaml`):**

| Agent(s) | Model | Rationale |
|----------|-------|-----------|
| Critic, Developer, Chain Synthesizer | frontier Claude model | Deep reasoning, code understanding, adversarial review |
| Auth / Injection / File / SSRF / XSS / AuthFlow / LogicFlaw specialists | balanced Claude model | Pattern recognition at scale; surveyor and specialists also drive a tool-loop |
| Surveyor, PoC Author | balanced Claude model | Structured output generation + tool use |
| Reporter, Dedup fallback, Hypothesis Verifier | cost-efficient Claude model | Mechanical validation and report-support tasks |

**ChatGPT-subscription assignments (`pipelines/openai.yaml`):**

The LiteLLM `chatgpt/` provider authenticates with a ChatGPT subscription through OAuth. `pipelines/openai.yaml` maps the agent roles to ChatGPT model strings; no `OPENAI_API_KEY` is required for this path.

---

## Pipeline Configuration (YAML)

Two production pipelines ship in the repo: `pipelines/default.yaml` (Claude via Anthropic API keys) and `pipelines/openai.yaml` (ChatGPT-subscription via LiteLLM's `chatgpt/` OAuth). A `pipelines/test.yaml` exists for test runs.

```yaml
# pipelines/default.yaml (abridged — see file for stage-toggle defaults)

cost_ceiling_usd: 2.00
max_hypotheses_to_verify: 10
sandbox_timeout_seconds: 120
verify_max_iterations: 7
developer_calls_per_agent: 7

models:
  critic: claude-opus-4-6
  developer: claude-opus-4-6                      # propose_setup (initial) + consult
  developer_followup: claude-sonnet-4-6           # propose_setup_followup classifier
  surveyor: claude-sonnet-4-6
  poc_author: claude-sonnet-4-6
  specialists: claude-sonnet-4-6
  reporter: claude-haiku-4-5-20251001
  dedup_fallback: claude-haiku-4-5-20251001
  hypothesis_verifier: claude-haiku-4-5-20251001

sandbox:
  wordpress_image: wordpress:latest
  db_image: mariadb:10.11
  wp_admin_user: admin
  wp_admin_pass: password
  wp_admin_email: admin@test.local
  wp_url: http://localhost:8080

vuln_dbs:
  wordfence:
    base_url: https://www.wordfence.com/api/intelligence/v2
    # no API key required for the production feed
  wpscan:
    base_url: https://wpscan.com/api/v3
    # api_key loaded from env: WPSCAN_API_KEY

stages:
  - intake
  - recon
  - hypothesis
  - triage
  - verify
  - dedup
  - report

# Per-stage opt-in features ship behind toggles (default false). See the
# full `pipelines/default.yaml` for the complete `intake.*`, `recon.*`,
# `hypothesis.*`, `triage.*`, `verify.*`, `dedup.*`, `report.*` blocks
# documented by the pipeline config schema.
```

A `chain` stage exists (`src/squadrone/stages/chain.py`) but runs only when `--chain` is passed on the CLI; it's not in the default stage list. When enabled, it writes `chains.json`, rewrites `hypotheses.jsonl` with chain annotations, and writes `chain_diagnostics.json` so a failed model call, insufficient hypotheses, and a valid empty chain result are distinguishable.

---

## Agents

### Roster

| # | Agent | Tier | Role |
|---|-------|-----------|------|
| 1 | Surveyor | balanced | Maps attack surface via `grep_plugin` / `glob_plugin` / `read_plugin_file` tool loop |
| 2 | Developer | frontier | WP-expert consultant + initial sandbox setup. Called via `consult_developer` tool |
| 3 | Auth Specialist | balanced | Missing cap checks, missing nonces, broken permission_callbacks |
| 4 | Auth-Flow Specialist | balanced | Login, password reset, 2FA, account creation flaws |
| 5 | Injection Specialist | balanced | SQLi, command injection, header injection |
| 6 | File-Ops Specialist | balanced | Path traversal, arbitrary file ops, LFI/RFI |
| 7 | SSRF/Deser Specialist | balanced | SSRF, XXE, PHP object injection, untrusted unserialize |
| 8 | XSS Specialist | balanced | Reflected, stored, DOM XSS |
| 9 | Logic-Flaw Specialist | balanced | Payment-flow bypasses, IPN trust, business-rule violations |
| 10 | Cross-File-XSS Specialist (optional) | balanced | Sanitise-on-write + read-raw-on-output patterns spanning multiple files |
| 11 | Hypothesis Verifier | cheap | Self-verification pass — drops fabricated `sink_code` / missed-guard claims |
| 12 | Chain Synthesizer (optional) | frontier | Cross-specialist exploit-chain reasoning |
| 13 | Critic | frontier | Adversarial triage against Wordfence + Patchstack scope rules |
| 14 | PoC Author | balanced | Writes exploit scripts from templates + `wp_login` / `xss_check` helpers; iterates with Developer's followup classifier |
| 15 | Developer Followup | cheap | After a failed PoC iteration, classifies failure as `setup` / `exploit_shape` / `poc_code` and proposes additional setup commands |
| 16 | Reporter | cheap | Drafts advisory markdown per finding, one per bounty program (Wordfence + Patchstack) |
| 17 | Dedup fallback (optional) | cheap | LLM similarity matching when structural dedup is inconclusive |

All specialists + surveyor receive the three plugin-scoped tools (`grep_plugin`, `glob_plugin`, `read_plugin_file`) plus `consult_developer`. The PoC author additionally receives the `wp_login` + `xss_check` helper modules at script-write time. See "PoC Templates" section for details.

### Developer agent — tool call spec

Specialists, Critic, and PoC Author all have `consult_developer` as a declared tool.
Limit: `developer_calls_per_agent` per agent turn (default 7, set in YAML).

```python
CONSULT_DEVELOPER_TOOL = {
    "type": "function",
    "function": {
        "name": "consult_developer",
        "description": (
            "Ask the WordPress developer expert a question about the codebase. "
            "Use when you need to understand what a piece of code does, whether a "
            "code path is reachable, what a WordPress API call returns, or why a "
            "payload may or may not work. Be specific — include the relevant code "
            "snippet and your exact question."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "Your specific question about the code"
                },
                "code_snippet": {
                    "type": "string",
                    "description": "The relevant code snippet you are asking about"
                },
                "context": {
                    "type": "string",
                    "description": "Any additional context"
                }
            },
            "required": ["question", "code_snippet"]
        }
    }
}
```

When an agent calls `consult_developer`, the agent runtime:
1. Intercepts the tool call
2. Calls the Developer agent with the question + code snippet + context
3. Returns Developer's response as the tool result
4. Continues the calling agent's conversation

---

## Pydantic Schemas

```python
# src/squadrone/schemas/

from pydantic import BaseModel
from enum import Enum
from typing import Optional
from datetime import datetime


# ── intake ───────────────────────────────────────────────────────

class IntakeArtifact(BaseModel):
    run_id: str
    plugin_slug: str
    plugin_version: str
    source_path: str
    file_count: int
    total_lines: int
    svn_url: str
    scanned_at: datetime


# ── recon ────────────────────────────────────────────────────────

class EntryPoint(BaseModel):
    type: str               # ajax_priv | ajax_nopriv | rest_route | shortcode | form_handler
    name: str
    file: str
    line: int
    handler_function: str
    requires_auth: bool
    has_nonce_check: bool
    has_capability_check: bool
    capability: Optional[str]

class Sink(BaseModel):
    type: str               # db_query | file_op | external_http | unserialize | eval | include
    function: str
    file: str
    line: int
    tainted_args: list[str]

class ReconArtifact(BaseModel):
    plugin_slug: str
    entry_points: list[EntryPoint]
    sinks: list[Sink]
    entry_to_sink_paths: dict[str, list[str]]
    raw_grep_hits: dict[str, list[str]]


# ── hypothesis ───────────────────────────────────────────────────

class BugClass(str, Enum):
    MISSING_CAP_CHECK    = "CWE-862"
    MISSING_NONCE        = "CWE-352"
    SQLI                 = "CWE-89"
    COMMAND_INJECTION    = "CWE-78"
    PATH_TRAVERSAL       = "CWE-22"
    ARBITRARY_FILE_WRITE = "CWE-434"
    SSRF                 = "CWE-918"
    XXE                  = "CWE-611"
    PHP_OBJECT_INJECTION = "CWE-502"
    XSS_REFLECTED        = "CWE-79"
    XSS_STORED           = "CWE-79"

class Confidence(str, Enum):
    HIGH   = "high"
    MEDIUM = "medium"
    LOW    = "low"

class Hypothesis(BaseModel):
    id: str
    specialist: str
    bug_class: BugClass
    entry_point: str
    file: str
    line: int
    sink: str
    taint_path: list[str]
    reasoning: str
    confidence: Confidence
    preconditions: str
    affected_versions: str

class HypothesesArtifact(BaseModel):
    plugin_slug: str
    hypotheses: list[Hypothesis]

class TriagedArtifact(BaseModel):
    plugin_slug: str
    accepted: list[Hypothesis]
    rejected: list[dict]    # {hypothesis_id, reason}
    merged: list[dict]      # {kept_id, merged_from_id, reason}


# ── finding ──────────────────────────────────────────────────────

class PoCStatus(str, Enum):
    SUCCESS = "success"
    FAILED  = "failed"
    PARTIAL = "partial"

class DedupStatus(str, Enum):
    NOVEL          = "novel"
    POSSIBLY_KNOWN = "possibly_known"
    KNOWN_DUPE     = "known_dupe"

class PoCAttempt(BaseModel):
    iteration: int
    script_path: str
    result: PoCStatus
    http_status: Optional[int]
    response_snippet: Optional[str]
    timing_seconds: Optional[float]
    error_log_snippet: Optional[str]
    developer_analysis: Optional[str]

class Finding(BaseModel):
    id: str
    hypothesis: Hypothesis
    poc_status: PoCStatus
    poc_script_path: str
    poc_attempts: list[PoCAttempt]
    evidence: dict
    confidence_runs: int
    dedup_status: DedupStatus
    dedup_matches: list[dict]
    cvss_estimate: Optional[str]
    suggested_fix: Optional[str]
```

---

## Agent Prompts

### Surveyor
```
You are a static analysis tool for WordPress plugins. Map the attack surface only —
do not find vulnerabilities.

Entry points: wp_ajax_{action}, wp_ajax_nopriv_{action}, register_rest_route(),
shortcode handlers, form submission handlers (admin-post.php), widget save/update.

Sinks: $wpdb->query/get_results/get_var/get_row with non-literal args, file_put_contents,
move_uploaded_file, unlink, include/require with variables, eval(), shell_exec(),
exec(), system(), passthru(), popen(), wp_remote_get/post with user-controlled URLs,
unserialize()/maybe_unserialize() with non-literal args.

For each entry point, note presence of wp_verify_nonce/check_ajax_referer and
current_user_can().

Output ONLY valid JSON matching ReconArtifact schema. No prose.
```

### Auth Specialist
```
You are a WordPress security specialist focused exclusively on authorisation bugs.
You have access to consult_developer (max 3 calls).

For every entry point evaluate:
1. CAPABILITY CHECK — is current_user_can() called before state-changing ops?
   What capability? Could a subscriber trigger this?
2. NONCE CHECK — is wp_verify_nonce() or check_ajax_referer() called before execution?
3. REST PERMISSION CALLBACK — is it set? Is it __return_true or null? (both = bug)

Confidence HIGH: check is clearly absent.
Confidence MEDIUM: check may exist upstream.
Confidence LOW: unusual preconditions required.

Output ONLY valid JSON — list of Hypothesis objects. No prose.
```

### Injection Specialist
```
You are a WordPress security specialist focused on injection vulnerabilities.
You have access to consult_developer (max 3 calls).

SQL injection — every $wpdb call:
- Concatenation in query/get_results/get_var/get_row → HIGH confidence SQLi
- Correct $wpdb->prepare() with %s/%d → SAFE
- User input inside the format string of prepare() → SQLi despite prepare()
- sprintf/str_replace query building → evaluate carefully

Command injection — shell_exec, exec, system, passthru, popen, proc_open:
- Any non-literal argument → evaluate escapeshellarg/cmd usage

Header injection — wp_redirect(), header() with user-controlled values.

Output ONLY valid JSON — list of Hypothesis objects. No prose.
```

### File Specialist
```
You are a WordPress security specialist focused on file operation vulnerabilities.
You have access to consult_developer (max 3 calls).

FILE UPLOAD — move_uploaded_file, wp_handle_upload:
  Extension allowlist? Server-side MIME check? Filename traversal possible?

FILE WRITE — file_put_contents, fwrite, copy:
  Target path user-controlled? realpath() + prefix check present?

FILE READ — file_get_contents, fopen, readfile:
  Path user-controlled? Could attacker read wp-config.php or /etc/passwd?

FILE DELETE — unlink, rmdir:
  Path user-controlled? Auth check before deletion?

INCLUDE — include/require with variable args:
  Variable user-controlled? Allowlist validation?

ZIP EXTRACTION — ZipArchive::extractTo:
  Filenames sanitised to prevent zip slip?

Output ONLY valid JSON — list of Hypothesis objects. No prose.
```

### SSRF/Deserialization Specialist
```
You are a WordPress security specialist focused on SSRF, XXE, and PHP object injection.
You have access to consult_developer (max 3 calls).

SSRF — wp_remote_get/post, curl_*, file_get_contents with http(s):
  URL user-controlled? wp_http_validate_url() only blocks some cases.
  Can attacker hit 169.254.x.x, 10.x, 127.x? Non-http schemes (file://, gopher://)?

XXE — simplexml_load_string, DOMDocument::loadXML, SimpleXMLElement:
  LIBXML_NOENT passed? libxml_disable_entity_loader() called? Input user-controlled?

PHP OBJECT INJECTION — unserialize(), maybe_unserialize():
  Argument user-controlled or from untrusted source?
  Does HMAC check happen BEFORE unserialize()?
  WP core + WooCommerce gadget chains exist.

Output ONLY valid JSON — list of Hypothesis objects. No prose.
```

### XSS Specialist
```
You are a WordPress security specialist focused on XSS. Lower priority than auth/injection.
You have access to consult_developer (max 3 calls).

Check all output operations for escaping:
- esc_html(), esc_attr(), esc_url(), wp_kses(), wp_kses_post(), esc_js()

STORED XSS — data saved to DB then rendered without escaping.
REFLECTED XSS — $_GET/$_POST/$_REQUEST rendered directly (admin notices, search, errors).
DOM XSS — plugin JS that reads URL params or postMessage, writes to innerHTML.

Set confidence HIGH only when escaping is clearly absent.

Output ONLY valid JSON — list of Hypothesis objects. No prose.
```

### Critic
```
You are an adversarial security reviewer. Find reasons each hypothesis is WRONG.
You have access to consult_developer (max 3 calls) to verify objections.

For each hypothesis ask:
1. Is there a nonce or capability check UPSTREAM that the specialist missed?
2. Is the sink actually reachable from this entry point via the call chain?
3. Is the input sanitised between source and sink?
   (sanitize_text_field, intval, absint, wp_kses, esc_sql, $wpdb->prepare)
4. Is the capability check wrong for the action? Subscribers and below only.
5. Is this already fixed in the version being analysed?

Output one verdict per hypothesis: accept | reject (with reason) | merge_with:{id}

Output ONLY valid JSON — a TriagedArtifact. No prose.
```

### PoC Author
```
You are an exploit developer writing Python proof-of-concept scripts using requests.
You have access to consult_developer (max 3 calls per iteration).

Rules:
- Use the provided template for the bug class as your starting point
- Target: {{ target_url }}
- Credentials: admin/password (admin), subscriber_user/password (subscriber)
- Never hit external URLs
- Script must print clear SUCCESS or FAILURE with evidence
- SQLi: time-based confirmation first, then data extraction
- Auth bypass: prove the privileged action executed (check DB state or response)
- File ops: write a benign marker file, verify it exists

When a previous attempt failed you will receive:
- The script that was tried
- HTTP response received
- Server error logs
- Developer analysis

Adjust based on feedback. Do not repeat the same payload.

Output the complete Python script only. No prose, no markdown fences.
```

### Reporter
```
You are a security disclosure writer. Write a professional vulnerability advisory in markdown.

Include:
1. Title: [Plugin Name] <= [version] — [Bug Class] in [function] ([CWE])
2. Summary: 2-3 sentence plain-English description
3. Affected versions
4. Vulnerability details: file, function, the bug, why it matters
5. Proof of concept: human-readable reproduction steps (not raw script)
6. Impact: what an attacker achieves
7. Suggested fix: concrete code change
8. CVSS v3.1 score estimate with vector string
9. Timeline: placeholder (researcher fills in)

Tone: professional, factual, no hype. Length: 400-600 words.
```

---

## LLM Gateway + Cache

```python
# src/squadrone/services/llm.py

import hashlib, json
import aiosqlite
import litellm
from tenacity import retry, stop_after_attempt, wait_exponential

CACHE_DB = "cache/llm.sqlite"

async def init_cache():
    async with aiosqlite.connect(CACHE_DB) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS llm_cache (
                cache_key  TEXT PRIMARY KEY,
                response   TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)
        await db.commit()

def _cache_key(model: str, messages: list, tools: list | None) -> str:
    payload = json.dumps(
        {"model": model, "messages": messages, "tools": tools}, sort_keys=True
    )
    return hashlib.sha256(payload.encode()).hexdigest()

@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=30))
async def call_llm(
    model: str,
    messages: list[dict],
    tools: list[dict] | None = None,
    max_tokens: int = 4096,
    budget_tracker=None,
) -> dict:
    key = _cache_key(model, messages, tools)

    async with aiosqlite.connect(CACHE_DB) as db:
        async with db.execute(
            "SELECT response FROM llm_cache WHERE cache_key = ?", (key,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return json.loads(row[0])

    response = await litellm.acompletion(
        model=model, messages=messages, tools=tools, max_tokens=max_tokens
    )

    if budget_tracker:
        budget_tracker.add(response.usage, model)

    result = response.model_dump()

    async with aiosqlite.connect(CACHE_DB) as db:
        await db.execute(
            "INSERT OR IGNORE INTO llm_cache VALUES (?, ?, datetime('now'))",
            (key, json.dumps(result))
        )
        await db.commit()

    return result
```

The LLM service adds the production behavior around this skeleton:

- **ChatGPT OAuth response aggregation** — normalizes streamed `chatgpt/` OAuth responses into the same message shape used by other LiteLLM providers.
- **`call_llm_oneshot()`** — thin wrapper for single-turn calls used by `DeveloperAgent.propose_setup` / `propose_setup_followup` / `consult` (these don't need the full agent runtime).
- **Rate-limit retry** — tenacity-backed exponential backoff on `litellm.exceptions.RateLimitError`.

The companion **`agents/transport/litellm_transport.py`** wraps `call_llm` in an agent loop that:
- applies Anthropic `cache_control` markers on the system message + first user message + last tool result (for Claude models only)
- traces every request/response/tool-call into `trace.jsonl`
- runs a **sliding-window history trim** (`_trim_history_for_budget`) that drops older tool-call cycles when accumulated context exceeds the configured budget
- forces final-output emission when the agent exhausts its iteration budget
- validates final output against the Pydantic schema and retries once on validation failure

`agents/developer.py::_parse_json_resilient` adds a bracket-balancing fallback for malformed JSON responses that embed complex PHP/SQL string values.

---

## Budget Tracker

```python
# src/squadrone/services/budget.py

COST_PER_1M = {
    "claude-opus-4-7":           {"input": 15.00, "output": 75.00},
    "claude-opus-4-6":           {"input": 15.00, "output": 75.00},
    "claude-sonnet-4-6":         {"input": 3.00,  "output": 15.00},
    "claude-haiku-4-5-20251001": {"input": 0.80,  "output": 4.00},
    # ChatGPT-subscription usage is quota-based; these rates are advisory
    # estimates for reporting.
    "chatgpt/gpt-5.4":           {"input": 3.00,  "output": 15.00},
    "chatgpt/gpt-5.3-codex":     {"input": 3.00,  "output": 15.00},
}

class BudgetExceededError(Exception):
    pass

class BudgetTracker:
    def __init__(self, ceiling_usd: float):
        self.ceiling = ceiling_usd
        self.spent = 0.0

    def add(self, usage, model: str) -> None:
        rates = COST_PER_1M.get(model, {"input": 3.0, "output": 15.0})
        cost = (
            usage.prompt_tokens * rates["input"] +
            usage.completion_tokens * rates["output"]
        ) / 1_000_000
        self.spent += cost
        if self.spent >= self.ceiling:
            raise BudgetExceededError(
                f"Budget ceiling ${self.ceiling:.2f} reached (spent ${self.spent:.2f})"
            )
```

---

## Verify Stage — Iteration Loop

```python
# src/squadrone/stages/verify.py (outline)

async def verify_hypothesis(
    hypothesis: Hypothesis,
    plugin_path: str,
    config: PipelineConfig,
    budget: BudgetTracker,
) -> Finding | None:

    async with SandboxManager(config.sandbox) as sandbox:
        await sandbox.boot()
        await sandbox.install_plugin(plugin_path)
        await sandbox.setup_test_users()

        attempts = []

        for iteration in range(1, config.verify_max_iterations + 1):

            # PoC Author writes/revises the exploit
            poc_script = await run_poc_author(
                hypothesis=hypothesis,
                previous_attempts=attempts,
                config=config,
                budget=budget,
            )

            # Runner executes against live sandbox
            result = await sandbox.run_poc(poc_script)

            attempt = PoCAttempt(
                iteration=iteration,
                script_path=save_script(poc_script, hypothesis.id, iteration),
                result=PoCStatus.SUCCESS if result.success else PoCStatus.FAILED,
                http_status=result.http_status,
                response_snippet=result.response[:500] if result.response else None,
                timing_seconds=result.elapsed,
                error_log_snippet=result.error_log[:500] if result.error_log else None,
                developer_analysis=None,
            )

            if result.success:
                confirm = await sandbox.run_poc(poc_script)
                attempt.result = (
                    PoCStatus.SUCCESS if confirm.success else PoCStatus.PARTIAL
                )
                attempts.append(attempt)
                break

            # Developer analyses failure before next iteration
            if iteration < config.verify_max_iterations:
                attempt.developer_analysis = await run_developer_debug(
                    hypothesis=hypothesis,
                    poc_script=poc_script,
                    run_result=result,
                    config=config,
                    budget=budget,
                )

            attempts.append(attempt)

        successful = [
            a for a in attempts
            if a.result in (PoCStatus.SUCCESS, PoCStatus.PARTIAL)
        ]
        if not successful:
            return None

        return Finding(
            id=next_finding_id(),
            hypothesis=hypothesis,
            poc_status=successful[-1].result,
            poc_script_path=successful[-1].script_path,
            poc_attempts=attempts,
            evidence=result.evidence,
            confidence_runs=len(successful),
            dedup_status=DedupStatus.NOVEL,
            dedup_matches=[],
        )
```

The shipping `stages/verify.py` adds:

- **`propose_setup_followup` classifier loop** — after a failed PoC iteration, the developer agent classifies the failure as `setup` (re-issue commands), `exploit_shape` (PoC approach is wrong — early-exit), or `poc_code` (script crashed — let PoC author retry with same setup).
- **Per-PoC-script helpers** — `wp_login.py` and `xss_check.py` are dropped next to the generated `iter_N.py` scripts so they can `from wp_login import wp_login` / `from xss_check import check_reflection` directly.
- **Structured `user_accounts` context** — the credential table provisioned by `sandbox.setup_test_users()` (5 default WP roles) is passed via `extra_context.user_accounts` to PoC author so it picks the lowest-privilege account that satisfies its hypothesis preconditions.
- **W3 persistent sandbox (opt-in)** — when `verify.persistent_sandbox: true`, one sandbox is booted per scan and DB/uploads snapshotted between hypotheses (cheaper for multi-finding plugins).

---

## Docker Sandbox

```yaml
# docker/docker-compose.yml.j2

services:
  db:
    image: mariadb:10.11
    environment:
      MYSQL_ROOT_PASSWORD: rootpass
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wpuser
      MYSQL_PASSWORD: wppass
    healthcheck:
      test: ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"]
      interval: 5s
      timeout: 5s
      retries: 10

  wordpress:
    image: wordpress:latest
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "{{ port }}:80"
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: wpuser
      WORDPRESS_DB_PASSWORD: wppass
      WORDPRESS_DB_NAME: wordpress
      WORDPRESS_DEBUG: "1"
      WORDPRESS_CONFIG_EXTRA: |
        define('SAVEQUERIES', true);
    volumes:
      - wp_data:/var/www/html
      - ./wp-init.sh:/docker-entrypoint.d/99-wp-init.sh

volumes:
  wp_data:
```

---

## Manual Review Sandbox

The automated verify stage uses short-lived Docker sandboxes to reproduce a
specific hypothesis. Squadrone also includes a manual review script for the
human validation step that happens before any disclosure:

```sh
python manual/wp_manual_sandbox.py --plugin-slug <slug>
python manual/wp_manual_sandbox.py --plugin-slug <slug> --plugin-version 1.2.3
python manual/wp_manual_sandbox.py --plugin-slug <slug> --reset
python manual/wp_manual_sandbox.py --plugin-slug <slug> --down
```

`manual/wp_manual_sandbox.py` creates a persistent WordPress + MariaDB Docker
Compose project under `manual/sandboxes/<project>/`, installs WordPress,
installs and activates the requested wordpress.org plugin, and provisions a
standard set of accounts:

| Login | Password | Role |
|---|---|---|
| `admin` | `password` | administrator |
| `subscriber_user` | `password` | subscriber |
| `contributor_user` | `password` | contributor |
| `author_user` | `password` | author |
| `editor_user` | `password` | editor |

The script allocates a free local port in the `8201-8299` range by default,
prints the WordPress URL, and prints the matching `docker compose` commands for
logs and teardown. The generated sandbox is intentionally separate from scan
run directories: it is for browser-driven reproduction, manual payload tuning,
and checking whether a generated report accurately describes the real plugin
behavior.

Design constraints:

1. **No dependency on prior scan artifacts.** A reviewer can boot a clean manual
   sandbox from only a plugin slug and optional version.
2. **Predictable credentials.** Default users match the roles used by generated
   PoCs so researchers can quickly test privilege boundaries.
3. **Persistent by default.** The manual sandbox stays up until `--down` or
   `--reset`, allowing iterative investigation across browser, WP-CLI, logs,
   and database state.
4. **Local-only scope.** The script targets localhost Docker environments and
   does not submit data to vulnerability programs or external services.

Special-purpose manual scripts can live outside the public source tree when a
finding needs bespoke reproduction logic.

---

## WP-CLI Wrapper Interface

```python
# src/squadrone/services/wp_cli.py

class WPCli:
    """Executes WP-CLI commands inside the running sandbox container."""

    async def create_user(self, login: str, role: str, password: str = "password") -> None: ...
    async def install_plugin(self, zip_path: str) -> None: ...
    async def activate_plugin(self, slug: str) -> None: ...
    async def get_option(self, option_name: str) -> str: ...
    async def set_option(self, option_name: str, value: str) -> None: ...
    async def get_query_log(self) -> list[str]: ...   # requires SAVEQUERIES=true
    async def get_error_log(self) -> str: ...
    async def db_query(self, sql: str) -> list[dict]: ...
    async def get_posts(self, post_type: str = "post") -> list[dict]: ...
```

---

## Vuln DB Integration

```python
# src/squadrone/services/vuln_db.py

class VulnMatch(BaseModel):
    source: str                 # "wordfence" | "wpscan"
    cve_id: Optional[str]
    title: str
    affected_versions: str
    bug_class: Optional[str]
    published_at: Optional[str]
    similarity_score: float     # 0.0–1.0

class VulnDBClient:
    async def lookup_wordfence(self, plugin_slug: str) -> list[VulnMatch]: ...
    # GET https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production
    # Cached once per process (it's the full feed); no API key required.

    async def lookup_wpscan(self, plugin_slug: str) -> list[VulnMatch]: ...
    # GET https://wpscan.com/api/v3/plugins/{slug}
    # Auth: Authorization: Token token=WPSCAN_API_KEY (optional — gracefully skipped if missing)

    async def lookup_all(self, plugin_slug: str) -> list[VulnMatch]: ...
    # Calls both providers; results merged. Missing keys log a warning, never fail.
```

> Earlier iterations queried Patchstack directly via its API; the production code switched to the Wordfence Intelligence v3 feed (no key required) plus the WPScan API (key-gated). Patchstack remains a submission *destination* for disclosure reports, not a dedup source.

---

## SQLite Schema

```sql
-- db/schema.sql

CREATE TABLE IF NOT EXISTS plugins (
    slug            TEXT PRIMARY KEY,
    last_scanned_at TEXT,
    last_version    TEXT,
    finding_count   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS runs (
    run_id        TEXT PRIMARY KEY,
    plugin_slug   TEXT,
    started_at    TEXT,
    finished_at   TEXT,
    status        TEXT,   -- running | complete | failed | budget_exceeded
    cost_usd      REAL,
    finding_count INTEGER DEFAULT 0,
    FOREIGN KEY (plugin_slug) REFERENCES plugins(slug)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id   TEXT PRIMARY KEY,
    run_id       TEXT,
    plugin_slug  TEXT,
    bug_class    TEXT,
    cwe          TEXT,
    confidence   TEXT,
    poc_status   TEXT,
    dedup_status TEXT,
    created_at   TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS disclosures (
    finding_id   TEXT PRIMARY KEY,
    submitted_to TEXT,   -- "wordfence" | "patchstack" | "wpscan" | "direct"
    submitted_at TEXT,
    cve_id       TEXT,
    status       TEXT,   -- submitted | acknowledged | patched | rejected
    notes        TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);
```

---

## PoC Templates

Two kinds of artefacts live in `src/squadrone/poc_templates/`:

- **Jinja2 skeletons (`*.py.j2`)** — bug-class starting points selected by `_select_template(bug_class)`. The PoC author treats them as a starting point and freely rewrites whole sections per hypothesis.
- **Importable Python helpers** — provisioned next to the generated `iter_N.py` script by `stages/verify.py` so the PoC can `from <helper> import …` directly:
  - **`wp_login.py`** — robust WordPress login (GET-then-POST flow with `wordpress_test_cookie` handled, multiple admin-bar markers checked). Replaces hand-rolled `session.post('/wp-login.php', …)` flows that routinely fail because the test cookie isn't primed.
  - **`xss_check.py`** — `html.parser`-based reflection check with delimiter-vs-payload-char compatibility detection. Replaces the prior heuristic substring check that produced the wp-statistics xss-001 false positive.

Example helper usage in a PoC script:

```python
from wp_login import wp_login
from xss_check import check_reflection

session = requests.Session()
result = wp_login(session, TARGET_URL, "subscriber_user", "password")
if not result.success:
    print(f"[-] FAILURE: {result.reason}")
    raise SystemExit(1)
# session is now authenticated; subsequent requests inherit the cookies
```

The j2 skeletons below are intentionally minimal — the PoC author prompt instructs them to import the helpers above for any login flow rather than hand-roll it.

```python
# poc_templates/sqli_timebased.py.j2

import requests, time

TARGET = "{{ target_url }}"
ACTION = "{{ ajax_action }}"
PARAM  = "{{ injectable_param }}"

PAYLOADS = [
    "' AND SLEEP(5)-- -",
    "' OR SLEEP(5)-- -",
    "%' AND SLEEP(5)-- -",
    "%' OR SLEEP(5)#",
    "1 AND SLEEP(5)",
    "1; SELECT SLEEP(5)-- -",
]

def test(payload: str) -> tuple[bool, float]:
    start = time.time()
    resp = requests.post(
        f"{TARGET}/wp-admin/admin-ajax.php",
        data={"action": ACTION, PARAM: payload},
        timeout=30,
    )
    elapsed = time.time() - start
    return elapsed > 4.0, elapsed

if __name__ == "__main__":
    print(f"[*] Testing SQLi: action={ACTION} param={PARAM}")
    for p in PAYLOADS:
        ok, t = test(p)
        if ok:
            print(f"[+] SUCCESS payload={p!r} delay={t:.1f}s")
            break
        print(f"[-] No delay ({t:.1f}s): {p!r}")
    else:
        print("[!] FAILURE: no SQLi confirmed")
```

```python
# poc_templates/auth_bypass.py.j2

import requests

TARGET   = "{{ target_url }}"
ACTION   = "{{ ajax_action }}"
USERNAME = "{{ test_username }}"
PASSWORD = "{{ test_password }}"

session = requests.Session()
session.post(f"{TARGET}/wp-login.php", data={
    "log": USERNAME, "pwd": PASSWORD,
    "wp-submit": "Log In", "redirect_to": "/wp-admin/",
})

resp = session.post(f"{TARGET}/wp-admin/admin-ajax.php", data={
    "action": ACTION,
    {{ extra_params }}
})

if resp.status_code == 200 and "error" not in resp.text.lower():
    print(f"[+] SUCCESS as {USERNAME}: {resp.text[:200]}")
else:
    print(f"[-] FAILURE status={resp.status_code}: {resp.text[:200]}")
```

---

## Project Structure

```
squadrone/
├── pyproject.toml
├── README.md
├── .env.example
├── docker/
│   ├── docker-compose.yml.j2
│   └── wp-init.sh
├── pipelines/
│   ├── default.yaml       # Anthropic API models
│   ├── openai.yaml        # ChatGPT-subscription via LiteLLM chatgpt/ OAuth
│   └── test.yaml          # cheap config for the test suite
├── db/
│   └── schema.sql
├── src/squadrone/
│   ├── cli.py
│   ├── orchestrator.py
│   ├── stages/
│   │   ├── intake.py
│   │   ├── recon.py
│   │   ├── hypothesis.py
│   │   ├── chain.py            # cross-specialist exploit-chain (opt-in via --chain)
│   │   ├── triage.py
│   │   ├── verify.py
│   │   ├── dedup.py
│   │   └── report.py
│   ├── agents/
│   │   ├── runtime.py          # AgentRuntime: tool dispatch + tracing
│   │   ├── transport/
│   │   │   ├── base.py             # AgentResult / AgentOutputError types
│   │   │   └── litellm_transport.py  # LiteLLMTransport + history-trim
│   │   ├── plugin_tools.py     # grep_plugin / glob_plugin / read_plugin_file
│   │   ├── tools.py            # consult_developer / read_plugin_file / request_additional_setup tool defs
│   │   ├── prompts_io.py       # loads markdown prompts from prompts/
│   │   ├── surveyor.py
│   │   ├── developer.py
│   │   ├── _specialist_base.py # shared run_specialist() helper
│   │   ├── auth.py
│   │   ├── auth_flow.py
│   │   ├── injection.py
│   │   ├── file_ops.py
│   │   ├── ssrf_deser.py
│   │   ├── xss.py
│   │   ├── logic_flaw.py
│   │   ├── cross_file_xss.py
│   │   ├── chain_synthesizer.py
│   │   ├── hypothesis_verifier.py
│   │   ├── critic.py
│   │   ├── poc_author.py
│   │   ├── reporter.py
│   │   ├── claim_validator.py
│   │   └── entry_point_validator.py
│   ├── prompts/
│   │   ├── _shared_rules.md
│   │   ├── _wp_idioms.md
│   │   ├── surveyor.md
│   │   ├── developer.md
│   │   ├── developer_setup.md
│   │   ├── developer_setup_followup.md
│   │   ├── critic.md
│   │   ├── chain_synthesis.md
│   │   ├── poc_author.md
│   │   ├── reporter_wordfence.md
│   │   ├── reporter_patchstack.md
│   │   ├── hypothesis_verifier.md
│   │   ├── entry_point_validator.md
│   │   ├── claim_validator.md
│   │   ├── wordfence_scope.md
│   │   ├── patchstack_scope.md
│   │   ├── plugin_selection_scope.md
│   │   └── specialists/
│   │       ├── auth.md, auth_flow.md, injection.md,
│   │       ├── file_ops.md, ssrf_deser.md, xss.md,
│   │       ├── logic_flaw.md, cross_file_xss.md
│   ├── services/
│   │   ├── llm.py             # LiteLLM gateway
│   │   ├── budget.py
│   │   ├── sandbox.py         # provisions 5 baseline users (admin + 4 roles)
│   │   ├── wp_cli.py
│   │   ├── wp_core.py
│   │   ├── svn.py
│   │   ├── vuln_db.py
│   │   ├── intake_helpers.py
│   │   ├── recon_helpers.py
│   │   ├── verify_helpers.py
│   │   ├── quality_gate.py    # deterministic evidence/severity/false-positive gates
│   │   ├── dedup_helpers.py
│   │   └── report_helpers.py
│   ├── poc_templates/
│   │   ├── wp_login.py         # robust GET-then-POST login helper (handles wordpress_test_cookie)
│   │   ├── xss_check.py        # html.parser-based reflection check
│   │   ├── sqli_timebased.py.j2
│   │   ├── sqli_union.py.j2
│   │   ├── auth_bypass.py.j2
│   │   ├── path_traversal.py.j2
│   │   ├── file_upload.py.j2
│   │   └── ssrf.py.j2
│   └── schemas/
│       ├── _base.py
│       ├── intake.py
│       ├── recon.py
│       ├── hypothesis.py
│       ├── finding.py
│       └── config.py
├── benchmarks/
│   ├── corpus.json
│   ├── runner.py
│   └── results/
└── tests/
    ├── unit/
    ├── integration/
    └── conftest.py
```

---

## CLI Interface

```bash
# Scan
squadrone scan <plugin-slug> [--config pipelines/default.yaml] [--budget 2.00]
                              [--version 1.2.3]              # pin a specific plugin version
                              [--no-triage]                  # skip Critic; pipe hypotheses straight to verify
                              [--ignore-scope]               # disable Wordfence/Patchstack scope filtering in triage
                              [--strict-quality|--no-strict-quality]
                              [--triage-votes 3]             # majority vote across independent Critic passes
                              [--chain]                      # run cross-specialist exploit-chain synthesis
                              [--cross-file-taint]           # enable cross-file XSS specialist
                              [--diff 1.21.0]                # PHP diff vs a prior version (n-day hunting)
                              [--resume <run_id>]            # resume an existing run
                              [--from <stage>]               # force re-run from a given stage (requires --resume)

# Batch / harness / review / disclosure
squadrone scan-batch plugins.txt                            # scan one plugin at a time by default
squadrone scan-batch plugins.txt --concurrency 3            # opt into parallel plugin scans
squadrone benchmark benchmarks/corpus.json [--split test]
squadrone review <run-id>
squadrone runs list
squadrone findings show <finding-id>
squadrone disclose <finding-id> --to patchstack --notes "Submitted via mVDP"
```

---

## Environment Variables

```bash
# .env.example
WORDFENCE_API_KEY=     # optional — dedup stage Wordfence Intelligence feed
WPSCAN_API_KEY=        # optional — dedup stage WPScan plugin DB
ANTHROPIC_API_KEY=     # for pipelines/default.yaml
OPENAI_API_KEY=        # optional for OpenAI API models
LITELLM_LOG=WARNING
```

`pipelines/openai.yaml` uses LiteLLM's `chatgpt/` provider which runs its own OAuth device-code flow on first use — no API key required, just complete the prompt in your browser.

If a vuln-DB key is missing the dedup stage logs a warning and skips that source — it does not fail the run.

---

## Key Design Rules (enforce throughout)

1. **Agents output Pydantic-validated JSON only.** Invalid → retry with error → fail after 2 retries.
2. **Stages are the only thing the orchestrator calls.** Agents invoked by stages only.
3. **No PoC, no report.** Unverified hypotheses never reach Reporter or researcher.
4. **Developer agent invoked via runtime, not direct import.** Specialists / Critic / PoC Author reach the developer via the `consult_developer` tool call (intercepted by `AgentRuntime`). The verify stage additionally invokes `DeveloperAgent.propose_setup` / `propose_setup_followup` directly via `call_llm_oneshot` — these are sandbox-setup helpers, not tool-loop calls.
5. **Hard budget ceiling via BudgetTracker.** Raises `BudgetExceededError` → orchestrator catches → marks run `budget_exceeded` → exits cleanly.
6. **All LLM calls go through `services/llm.py`.** Never call `litellm` directly from agent or stage code.
7. **Sandbox always torn down** even on exception — use async context manager.
8. **No auto-submission.** System writes `report_<id>_<program>.md`. Researcher submits manually.
9. **Prompt text in `/prompts/*.md` files.** Not hardcoded in Python.
10. **All stage outputs are JSON files on disk.** Never pass large objects in memory between stages.
11. **No new transports.** `LiteLLMTransport` is the only agent transport. New providers are added by passing the right model string through LiteLLM, not by writing a new transport class.

---

## Responsible Disclosure

- Researcher manually reviews ALL findings before any disclosure
- Nothing is auto-submitted anywhere
- Dedup stage checks Wordfence Intelligence + WPScan before anything reaches researcher
- `possibly_known` findings require explicit researcher sign-off before disclosure
- Track disclosure status in `disclosures` table
