# Shared source-review rules

## Coverage ledger

Return exactly one coverage disposition for every `coverage_targets` item:

- `candidate`: the item contributes to an emitted hypothesis
- `reviewed`: the complete reachable path was reviewed and no candidate remains
- `unreachable`: the registration/operation is dead or cannot be reached in the shipped plugin; cite why

Never omit an item. `reason` must name the handler, guard, sanitizer, dead-code
fact, or source path that supports the disposition. `evidence_locations` must
include the assigned item's exact `file:line` and any handler/guard locations
supporting the decision. You must obtain every cited line from
`read_plugin_file` during this batch; manifest text alone is not reviewed source.
When an assigned item has `column` greater than 1 on a minified line, use
`read_plugin_file` with that `start_column`; reading only the beginning of the
same line does not count as reviewing the item.
The `reviewer` value must be the exact review area named in your area prompt.
For `candidate`, `hypothesis_ids` must name the hypotheses supported by that
item. For `reviewed` and `unreachable`, return an empty `hypothesis_ids` list.

## Source grounding

Every hypothesis must quote the exact dangerous expression in `sink_code` and
cite its real `file` and `line` from a recent `read_plugin_file` result. Read the
complete callback and every plugin helper on the claimed path. A 15-line window
is not enough to assert that a guard or sanitizer is absent.

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

Output only this JSON shape:

```json
{
  "hypotheses": [
    {
      "id": "the supplied hypothesis_id_prefix plus a unique suffix",
      "specialist": "the exact assigned review area",
      "bug_class": "a canonical CWE id or supported CWE-79 variant",
      "entry_point": "the exact external route",
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
        "source": "attacker-controlled input",
        "control": "nearest effective or missing control",
        "sink": "dangerous operation",
        "reachable_path": "entry -> helpers -> sink",
        "boundary": "crossed security boundary",
        "impact": "demonstrated CIA outcome",
        "counterevidence": "nearby contrary evidence considered",
        "proof_gaps": "one narrow runtime question"
      }
    }
  ],
  "coverage": [
    {
      "item_id": "cov-0001",
      "reviewer": "the exact assigned review area",
      "status": "candidate | reviewed | unreachable",
      "reason": "source-grounded disposition",
      "evidence_locations": ["assigned/file.php:123", "handler/file.php:456"],
      "hypothesis_ids": ["batch-prefix-001"]
    }
  ]
}
```

Inside `hypotheses`, use exactly `id`, `specialist`, `bug_class`, and
`confidence`; do not substitute `hypothesis_id`, `reviewer`,
`vulnerability_class`, or `cwe`. Return every required field even when fixing a
prior response.
