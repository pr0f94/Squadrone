# Shared source-review rules

## Coverage ledger

Return exactly one coverage disposition for every `coverage_targets` item:

- `candidate`: the item contributes to an emitted hypothesis
- `reviewed`: the complete reachable path was reviewed and no candidate remains
- `unreachable`: the registration/operation is dead or cannot be reached in the shipped plugin; cite why
- `unreviewed`: source or reachability remains unresolved, including when forced
  finalization occurs before the complete path can be established

Never omit an item. `reason` must name the handler, guard, sanitizer, dead-code
fact, or source path that supports the disposition. `evidence_locations` must
include the assigned item's exact `file:line` and any handler/guard locations
supporting the decision. You must obtain every cited line from a
`read_plugin_file` or `read_plugin_ranges` result during this batch; manifest
text alone is not reviewed source.
When an assigned item has `column` greater than 1 on a minified line, use
`read_plugin_file` with that `start_column`; reading only the beginning of the
same line does not count as reviewing the item.
The `reviewer` value must be the exact review area named in your area prompt.
For `candidate`, `hypothesis_ids` must name the hypotheses supported by that
item. For `reviewed`, `unreachable`, and `unreviewed`, return an empty
`hypothesis_ids` list. If forced finalization leaves source or reachability
unresolved, return `unreviewed`; never convert an incomplete trace into
`reviewed` or `unreachable` merely to finish the batch.

On a retry, `prior_incomplete_review` is non-authoritative progress from the
first pass, not source evidence. Re-read every cited location used in the final
decision. Continue its concrete proof gaps and check alternate callers before
repeating broad searches; do not inherit its conclusions or turn an earlier
assumption into proof.

## Source grounding

Every hypothesis must quote the exact dangerous expression in `sink_code` and
cite its real `file` and `line` from a recent `read_plugin_file` or
`read_plugin_ranges` result. Read the complete callback and every plugin helper
on the claimed path. A 15-line window is not enough to assert that a guard or
sanitizer is absent.

Source presence is not branch reachability. When a helper contains conditional,
fallback, or mutually exclusive dangerous operations, trace the actual source
through the branch condition and cite the operation that this input executes.
Do not anchor a hypothesis to a nearby sibling branch merely because it has the
same sink class. When two operations are genuine fallbacks on the same reachable
condition, quote the complete source expression containing both.

Trace both directions:

1. From each external handler forward to a guard, sanitizer, sensitive
   operation, stored value, or response.
2. From each assigned sensitive operation backward to a realistic external
   source.
3. For persistent input, continue from the write through the later read/render
   path and identify the natural victim.

`direct_php` entries are shipped scripts that can execute through their own URL,
without a WordPress hook registration. Inspect them as independent request
routes, including when a dispatcher such as `->run()` reads request data inside
a dependency. A nonce or capability check on one WordPress callback does not
protect a shared sink reached from a separate script. Directory-near
`direct_php` entries may be included as conservative context for sink batches;
trace them before deciding whether they reach the assigned operation.

`direct_php_candidate` entries have a top-level bootstrap and dispatcher but no
visible top-level request signal. Review them for delegated request handling,
but do not assume they are directly web-reachable, unauthenticated, or
independent of WordPress. Establish those facts from source before emitting a
hypothesis.

Coalesce nearby assigned locations into range reads when practical. Leave tool
calls available to trace callers, alternate routes, guards, and downstream
effects instead of spending one call on every individual sink line.

Bundled dependencies and built JavaScript are inspectable. Review dependency
code when the plugin path reaches it; do not report a dependency issue merely
because vulnerable-looking code exists in `vendor`.

## Candidate bar

Keep one actor/configuration contract across `preconditions`,
`evidence_summary.attacker_role`, source control, and impact. Name privileged
victims and trusted setup actors separately. Do not lower the attacker role
because that role is mentioned in counterevidence or would be more interesting.
Missing plugin-level authorization does not remove upstream WordPress checks.
Prove the concrete external write/trigger path, including core content filtering
and callback prerequisites, or explicitly retain the missing fact as a proof gap.
An unavailable developer consultation is not agreement or supporting evidence.

Set `affected_versions` to the exact supplied `plugin_version` inspected in this
run. One source tree does not establish "and earlier", "all versions", a range,
or a version boundary inferred from plugin history. If the inspected version is
unavailable, state that uncertainty rather than inventing a version scope.

Emit only when all of these are concrete:

- lowest realistic attacker role and exact shipped configuration
- attacker-controlled source and exact reachable callback/helper path
- nearest effective or bypassed nonce, capability, ownership, token, validation, or escaping control
- dangerous operation and actual security outcome
- a plain confidentiality, integrity, or availability consequence
- nearby counterevidence and one narrow runtime proof gap

The structured `security_outcome` dimensions must agree with the impact text.
Mark each demonstrated confidentiality, integrity, or availability dimension as
`low` or `high`; never leave all three as `none` while claiming disclosure,
file modification, deletion, code execution, or loss of availability.

A normal victim action such as opening the plugin's submissions page can be a
valid stored-XSS trigger. Enabling a shipped feature through its intended UI is
also a valid prerequisite, even when the feature is disabled by default, if its
security subsettings remain at the defaults for that feature. State the toggle
and subsettings precisely. An administrator disabling or weakening a security
control, granting an extra capability, modifying source, enabling debug behavior,
or installing another component is not a valid prerequisite. Absence of a WAF
is normal and is not a precondition.

Object authorization and attribute authorization are separate questions. Object
ownership does not grant authority over every attribute. For a generic write
whose field/key name is request-controlled, trace the name as well as the value
and prove a server-side allowed-key set excludes protected attributes before
marking a current or newly created object safe.

Do not emit admin-only behavior, self/own-object behavior that cannot change a
protected attribute or cross a broader security boundary, cosmetic changes,
public counters, open redirects, HTML/CSS-only injection, generic HTTP 200
responses, or primitives with no demonstrated CIA consequence.

## Evidence schema

Every hypothesis must populate `evidence_summary` with short concrete values for
`attacker_role`, `source`, `control`, `sink`, `reachable_path`, `boundary`,
`impact`, `counterevidence`, and `proof_gaps`.
Use the supplied `hypothesis_id_prefix` when choosing hypothesis IDs; the runner
will canonicalize them when the batch is checkpointed.

Hypotheses may also include these backward-compatible lifecycle fields:

- `injection_order`: `direct`, `second`, or `null`;
- `storage_boundary`: `option`, `metadata`, `transient`, `custom_table`,
  `other`, or `null`;
- `impact_labels`: a duplicate-free list whose only currently supported member
  is the executable-outcome label `potential_rce`. That label is valid only for
  an exact CWE-434 arbitrary file upload/write hypothesis.

Omit optional fields when they do not apply. If included but inapplicable, use
`null` for `injection_order`/`storage_boundary` and an empty list for
`impact_labels` (never `null` for the list). A
CWE-89 candidate that claims a persistent/deferred write-read lifecycle must set
`injection_order` to `second` and must set a non-null `storage_boundary`; a
direct CWE-89 candidate may set `injection_order` to `direct` with
`storage_boundary` null. These labels are metadata, not proof.

The following `evidence_summary` keys are optional globally but mandatory for
the family that invokes them:

- a second-order CWE-89 candidate must set source-grounded `storage_writer`,
  `storage_identity`, `trigger`, and `write_success_marker`, and must truthfully
  set `same_actor_lifecycle` to a boolean and `verification_oracle` to `timing`
  or `response_marker`, identifying the exact
  external writer, normalized storage tuple, later read-to-SQL trigger, and exact
  response body fragment emitted only after that writer successfully persists the
  value. The marker must be trimmed printable ASCII, 8–256 characters, contain at
  least five distinct non-space characters case-insensitively, and must not be a
  generic token such as `1`, `ok`, `saved`, `success`, `true`, or `updated`;
  `storage_identity` must begin with the exact declared storage-boundary prefix:
  `option:`, `metadata:`, `transient:`, `custom_table:`, or `other:`, followed
  by a non-empty normalized identity. Printable Unicode is valid in the identity;
  automatic verification is timing-only and the parent-owned proxy measures the
  natural trigger latency. If source establishes only a response-visible SQL
  effect, preserve the exact source-valid hypothesis with
  `verification_oracle: "response_marker"` for `manual_review`; do not discard
  it or claim timing reachability. Only `same_actor_lifecycle: true` together
  with `verification_oracle: "timing"` is ready for automatic verification;
- a candidate with `impact_labels: ["potential_rce"]` must set source-grounded
  `code_execution_path` and `code_execution_sink`, identifying every post-write
  step and the exact include, autoload, interpreter dispatch, command execution,
  or equivalent terminal operation. A web-server SAPI dispatch of a written
  path counts as interpreter dispatch only when the exact served path,
  deterministic filename/extension, and direct request route are source-proven;
  the deployed server actually executing that path remains the one narrow
  runtime fact recorded in `proof_gaps`.

For CWE-78, CWE-94, or second-order CWE-89 only, optional
`verification_preflights` may be an ordered list of 1–8 unique, source-proven
read-only requests required before the proof request (for example, to render a
plugin form or acquire its nonce). Each item must be exactly `GET
/origin-relative/path` or `HEAD /origin-relative/path`, with only literal,
non-empty, unique query dispatch pairs when source requires them. Do not append
prose, fragments, alternatives, absolute URLs, form/JSON fields, or a
state-changing request. Preserve exact runtime order and omit the key entirely
when no plugin-specific preflight is required. Built-in WordPress login and REST
identity/nonce setup are not declared here.

Use `impact_labels: ["potential_rce"]` only when the root-cause primitive,
attacker-controlled executable write, and complete source path to the concrete
code-execution sink are proven, with one narrow runtime fact remaining. Do not
emit it for a mere upload/write primitive, dangerous extension, public URL, or
inferred web-server execution without a source-grounded execution sink. It must
not upgrade the structured CIA outcome or replace the required source path and
proof gap.

For an HTTP hypothesis, `entry_point` is a machine-readable transport seed, not
prose. Use exactly `METHOD /origin-relative/path`, optionally followed by one or
more source-proven fixed dispatch query pairs such as `?mode=submit&view=public`,
or one exact standard WordPress action hook: `wp_ajax_nopriv_ACTION`,
`wp_ajax_ACTION`, `admin_post_nopriv_ACTION`, or `admin_post_ACTION`. Put attacker
role, runtime signatures or tokens, UI workflow, and explanatory text in
`preconditions` or `evidence_summary`, never in `entry_point`. Preserve the
leading `/`; do not emit a bare `?query`, an absolute URL, a callback description,
or alternative routes in one value. Do not invent a query pair for a queryless
route.

For a second-order CWE-89 hypothesis, `entry_point` must be the legitimate
attacker-reachable **storage writer** transport, never the later SQL trigger.
Its `evidence_summary.trigger` must begin with the same machine-readable format
for the distinct natural trigger (`METHOD /origin-relative/path` or one exact
standard WordPress action hook), optionally followed by ` -> callback -> sink`
source context. For example: `POST /wp-admin/admin-ajax.php?action=save_sort` as
the writer and `GET /wp-admin/admin.php?page=reports -> render_reports ->
$wpdb->get_results` as the trigger. A cron event, CLI command, or other non-HTTP
trigger may support manual review; preserve an otherwise source-valid candidate
for the critic to route there rather than treating verifier coverage as source
counterevidence. Do not hide multiple writer or trigger alternatives in either
field.

When the source is an HTTP request value, `evidence_summary.source` must identify
one exact, source-proven wire location and its key when applicable. Non-exhaustive
examples include `POST form field <name>`, `multipart file field <name>`, `query
parameter <name>`, `JSON field <name>`, `path parameter <name>`, `header <name>`,
and `cookie <name>`; for an unnamed raw or XML body, identify that exact encoding.
Include `relative/source-file:line — <verbatim source expression>` from a
source-read result (`read_plugin_file` or `read_plugin_ranges`). Do not write
alternatives such as `JSON or form`, and do not substitute a UI label, DTO/model
property, or storage key for the actual wire key. Record every proven rename in
`taint_path`; emit separate hypotheses for independently reachable alternative
transports.

Automatic verification currently binds only one top-level query, form, or JSON
field. A source-valid header, cookie, path parameter, raw body, XML body,
multipart field, or nested field is still a valid security lead: preserve its
exact transport and field encoding in the hypothesis and keep it as a candidate
for the critic to route to `manual_review`; do not reject, discard, or relabel it
as invalid merely because the automatic verifier cannot encode it. Apply the
same rule to a source-valid second-order flow whose writer and trigger require
different actor identities: preserve the exact lifecycle for manual review
rather than erasing the lead or claiming `same_actor_lifecycle: true`.

Output only this JSON shape:

```json
{
  "hypotheses": [
    {
      "id": "the supplied hypothesis_id_prefix plus a unique suffix",
      "specialist": "the exact assigned review area",
      "bug_class": "a canonical CWE id or supported CWE-79 variant",
      "entry_point": "POST /origin-relative/path",
      "file": "the sink source file",
      "line": 123,
      "sink": "the dangerous operation",
      "sink_code": "the exact source expression",
      "taint_path": ["external source", "helper", "sink"],
      "reasoning": "why the controls do not stop the demonstrated outcome",
      "confidence": "high | medium | low",
      "preconditions": "lowest role and shipped configuration",
      "affected_versions": "the source-grounded affected range",
      "security_outcome": {
        "confidentiality": "none | low | high",
        "integrity": "none | low | high",
        "availability": "none | low | high",
        "description": "plain CIA consequence"
      },
      "evidence_summary": {
        "attacker_role": "lowest demonstrated role",
        "source": "POST form field exact_name; relative/source-file:123 — $_POST['exact_name']",
        "control": "nearest effective or missing control",
        "sink": "dangerous operation",
        "reachable_path": "entry -> helpers -> sink",
        "boundary": "crossed security boundary",
        "impact": "demonstrated CIA outcome",
        "counterevidence": "nearby contrary evidence considered",
        "proof_gaps": "one narrow runtime question",
        "storage_writer": "family-specific: exact external storage writer and source locations",
        "storage_identity": "family-specific: normalized option/metadata/transient/table/other tuple",
        "trigger": "family-specific: later request/hook/job and read-to-sink callback chain",
        "write_success_marker": "family-specific: exact specific response body fragment emitted after a successful persistent write",
        "same_actor_lifecycle": true,
        "verification_oracle": "family-specific: timing for automatic second-order SQLi; response_marker for manual review only",
        "code_execution_path": "family-specific: every source-grounded post-write execution step",
        "code_execution_sink": "family-specific: exact terminal code-execution operation and location",
        "verification_preflights": ["GET /source-proven/plugin/form?literal=dispatch"]
      },
      "injection_order": "direct | second | null",
      "storage_boundary": "option | metadata | transient | custom_table | other | null",
      "impact_labels": ["potential_rce"]
    }
  ],
  "coverage": [
    {
      "item_id": "cov-0001",
      "reviewer": "the exact assigned review area",
      "status": "candidate | reviewed | unreachable | unreviewed",
      "reason": "source-grounded disposition",
      "evidence_locations": ["assigned/file.php:123", "handler/file.php:456"],
      "hypothesis_ids": ["batch-prefix-001"]
    }
  ]
}
```

Inside `hypotheses`, use the required keys shown above and only the three
declared optional lifecycle keys when applicable. In particular, use exactly `id`,
`specialist`, `bug_class`, and `confidence`; do not substitute `hypothesis_id`, `reviewer`,
`vulnerability_class`, or `cwe`. Return every required field even when fixing a
prior response. The family-specific `evidence_summary` keys in the illustrative
shape are not universal placeholders: omit each one entirely unless the
corresponding family contract above requires real source-grounded evidence.
