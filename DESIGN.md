# Squadrone Design

## Objective

Squadrone is an automated WordPress plugin vulnerability research pipeline. Its
success condition is not a suspicious code pattern. It is a source-grounded,
clean-state reproduced vulnerability with a concrete confidentiality,
integrity, or availability impact and a realistic CVE disclosure route.

The design optimizes for:

1. Broad review of shipped attack surface.
2. Low false-positive output.
3. Minimal human intervention before final disclosure review.
4. Explicit artifacts for every consequential decision.
5. A small fixed methodology instead of combinatorial feature modes.

Squadrone does not auto-submit reports, test remote production systems, or
claim that a pattern, HTTP status, reflection, or blind callback is itself a
vulnerability.

## Pipeline

```text
plugin slug
  -> intake
  -> deterministic coverage + threat mapping
  -> four accountable source reviews
  -> citation verifier
  -> full-source critic
  -> technical quality gate
  -> disclosure routing + ranking
  -> clean sandbox proof + confirmation
  -> confirmed CVSS
  -> known-vulnerability dedup
  -> private report drafts
```

### 1. Intake

Intake obtains the latest WordPress.org release unless a version is explicitly
pinned. It uses the official plugin ZIP and falls back to SVN for historical
versions. Latest-version scans reject components that WordPress.org reports as
closed.

Output: `intake.json`.

### 2. Coverage And Threat Mapping

`services/coverage.py` deterministically enumerates production PHP,
JavaScript, TypeScript, template, distribution, and build files. It excludes
tests, examples, documentation, language packs, VCS metadata, and
`node_modules`. Bundled dependencies are listed separately and remain readable
when a plugin call path enters them.

The inventory includes:

- AJAX, REST, admin-post/form, shortcode, block, WooCommerce AJAX/API, webhook,
  and selected request-lifecycle callbacks
- SQL, command, HTTP, XML, deserialization, and file operations
- option/object writes used as persistent-input lifecycle anchors
- authentication state and role/capability changes
- DOM HTML and JavaScript execution sinks in built frontend code

Generic reads and output calls are not independent ledger items. Callback
registrations are assigned to both authorization and XSS workflow review, and
reviewers follow reads/renders within the owning callback or persistence
lifecycle; enumerating
every `get_option()`, metadata read, and `echo` previously created hundreds of
shallow tasks without representing additional security boundaries.

The Surveyor validates and enriches this minimum inventory, resolves dynamic
registrations, follows handlers/helpers, and produces the plugin threat map:
sensitive objects, roles, capabilities, workflows, and persistent write/read
lifecycles.

Outputs: `recon.json` and initial `coverage.json`.

### 3. Source Review

Four reviewers own distinct security questions; one workflow can be assigned to
more than one reviewer when it crosses those questions:

| Review area | Responsibility |
|---|---|
| `authorization_workflows` | Object ownership, capabilities, state transitions, protected options/content/files, CSRF outcomes, mass assignment |
| `injection_files` | SQL/command injection, traversal, file operations, SSRF impact, XML, deserialization and gadgets |
| `xss_lifecycle` | Reflected callback-to-render paths, attacker write/persistence/render lifecycles, victim path, built JS, browser execution |
| `authentication` | Login/session state, recovery, magic links, token lifecycle, practical crypto/randomness bypass |

Each reviewer gets source-local batches of at most a bounded number of coverage
items and a compact recon view containing only related entry points, sinks, and
call edges. Every batch starts with a fresh model context while unrestricted
range-aware source tools remain available. This prevents the full recon and old
tool history from being resent on every turn.

For each item the reviewer must return `candidate`, `reviewed`, or
`unreachable`, cite the assigned `file:line` from an actual source-tool read,
and link every candidate to an emitted hypothesis. Deterministic targets retain
their match column, and minified-line targets count as read only when the tool
window includes that column. Incomplete batches retry once and then fail
explicitly; they are never silently treated as covered.

A hypothesis must include the exact sink expression and location, lowest
attacker role, source-to-outcome path, closest control, security boundary,
counterevidence, narrow runtime proof gap, and plain CIA consequence.

Outputs: `review_batches/<area>/`, `hypotheses_<area>.jsonl`,
`coverage_<area>.json`, updated `coverage.json`, and `hypotheses.jsonl`.

### 4. Verification And Critic Review

The low-cost hypothesis verifier has one job: reject a fabricated citation or a
contradiction visible in the cited source window. It does not attempt a second,
partial vulnerability methodology.

The Critic can read any plugin file. It re-derives complete callbacks and
helpers, attempts to disprove every claim, checks default configuration and the
lowest role, and decides technical validity without considering bounty scope.

The deterministic quality gate then requires:

- an exact file, line, and sink quote
- an explicit attacker source and reachable path
- a real security boundary
- at least one concrete CIA dimension
- no cosmetic-only, unsafe-configuration-only, or primitive-only claim

No CVSS number is guessed before runtime proof. Pre-verification severity is
only an unscored priority used for ranking.

### 5. Scope And Ranking

Program eligibility is separate from technical validity. Current
Wordfence/Patchstack rules route eligible candidates; valid but ineligible
items are `deferred`. This prevents program policy from being mislabeled as a
source-code false positive.

The route evaluates vulnerability type, attacker role, and impact. It assumes
the target was selected using `plugin_selection_scope.md`; install count,
vendor exclusions, researcher tier, and Patchstack mVDP enrollment are asset
metadata and are not inferred from plugin source.

Ranking happens after technical quality and scope filtering. It prioritizes
lower attacker privilege, greater demonstrated CIA impact, fewer
configuration preconditions, and stronger source confidence. Only then is
`max_hypotheses_to_verify` applied. Candidates below the cap are also deferred.

Output: `triaged.json`, `triaged.jsonl`, and `quality_gate_triage.json`.

### 6. Sandbox Proof

The verifier installs the unmodified plugin in an isolated WordPress/MariaDB
Docker stack and creates baseline WordPress roles. The Developer proposes only
legitimate prerequisite setup. Setup that directly seeds an exploit payload
into storage invalidates the proof.

Every PoC emits one structured observation:

```json
{
  "schema_version": 1,
  "verdict": "vulnerable",
  "oracle": "response_marker",
  "attacker_role": "subscriber",
  "request": {"method": "POST", "url": "http://localhost/..."},
  "attack": {"observed": true},
  "control": {"observed": false},
  "impact": {
    "confidentiality": "high",
    "integrity": "none",
    "availability": "none",
    "description": "..."
  }
}
```

The sandbox validates class-specific fields rather than searching stdout for a
success word:

| Oracle | Minimum evidence |
|---|---|
| `timing` | At least three attack/control samples and a material median differential |
| `response_marker` | Unique private marker in attack and absent from control |
| `state_change` | Different before/after state only for attack |
| `authorization` | Protected effect allowed for attack and denied for control |
| `cross_object_access` | Distinct attacker/owner and private marker only in attack |
| `callback` | Attack-only callback carrying a unique sensitive marker |
| `browser_execution` | JavaScript execution for attack and not control |
| `file_effect` | Observed path plus SHA-256 marker, absent for control |

Before each attempt, Squadrone snapshots the full database and `wp-content`.
After an oracle passes, it strictly restores that state and runs the exact same
script again. Snapshot/restore errors fail closed. Only a successful
confirmation creates a `Finding`; historical `partial` values remain parseable
but are never accepted.

Output: `verifications/<hypothesis_id>/` and `findings.jsonl`.

### 7. Scoring, Deduplication, And Reports

CVSS v3.1 base metrics are calculated after confirmation from the observed
attacker role, vulnerability interaction/scope semantics, and CIA dimensions.
The exact vector and score are stored in the finding.

Deduplication checks Wordfence Intelligence and WPScan and distinguishes exact
known paths from potentially related issues. Reports are generated only for a
confirmed, evidence-complete, non-duplicate finding that still meets the target
program's current rules.

Outputs: updated `findings.jsonl` and
`report_<finding_id>_<program>.md`.

## Configuration Surface

Pipeline YAML intentionally contains only operational controls:

- model names and per-role reasoning settings
- cost ceiling and candidate cap
- verification iterations and timeouts
- developer consultation cap
- Docker image/account settings
- persistent sandbox reuse, failure diagnostics, and screenshots
- vulnerability database endpoints

Coverage, source tools, reviewer areas, technical quality, negative controls,
clean confirmation, scope routing, and report grading are fixed behavior.

The LLM budget is reserved conservatively before uncached calls. Completed
responses are charged and returned before another call can be rejected, so a
ceiling does not discard an already-paid batch result.

The public scan flags are:

```text
scan:       --config --budget --version --resume --from --verbose
scan-batch: --concurrency --config --budget --version --verbose
```

## Benchmark Semantics

Every corpus item is a vulnerable/fixed version pair. Metrics distinguish:

- hypothesis recall at 1/3/10 on vulnerable versions
- clean-PoC verified recall
- confirmation rate for target hypotheses
- fixed-version target false-positive rate
- paired verified precision
- cost per confirmed target

The runner never counts an unverified hypothesis as a finding. Paired precision
only measures discrimination for the labeled target vulnerability; unrelated
findings are not silently labeled false positives.

## Persistence And Recovery

Run artifacts are the stage-level source of truth. SQLite indexes runs,
findings, disclosures, and cache data for lookup. `decision_ledger.jsonl`
records every consequential decision. JSON/JSONL writes are atomic where
possible, and malformed finding rows are quarantined during resume.

## Known Limits

- Static registration and call-graph extraction is conservative and cannot
  resolve every dynamic PHP pattern. The Surveyor must validate and augment it.
- Generated PoCs remain test programs, not mathematical proof. Their source and
  measured output must still be reviewed before disclosure.
- Program rules and asset thresholds change. Scope references include their
  checked date and must be refreshed when official rules change.
- A corpus labeled for one CVE cannot determine whether an unrelated finding is
  valid; benchmark metrics therefore avoid claiming global precision.
