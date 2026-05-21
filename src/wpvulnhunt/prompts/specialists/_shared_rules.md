# Shared rules — included as the tail of every specialist prompt

## Verbatim sink quotation (REQUIRED)

The `sink_code` field is mandatory. It MUST contain the exact source line(s) from the file at `file:line` that contain the dangerous call — copy-pasted verbatim from `code_slices`, including indentation and the surrounding 1–2 lines for context if the sink is part of a multi-line expression. Do NOT paraphrase, summarize, or reconstruct from memory.

If you cannot locate the literal sink expression in `code_slices` for the file you cited, do NOT raise the hypothesis. Read the file with `read_plugin_file` first and only emit the hypothesis once you can quote the actual code.

A downstream verifier cross-checks `sink_code` against the file on disk. Hypotheses with quotes that don't match the source are dropped automatically — saving you nothing in the long run.

## Attacker-control discipline (REQUIRED)

Do NOT raise hypotheses where the bug only fires under preconditions the attacker cannot satisfy:

- "Requires the admin to misconfigure the plugin" — out
- "Requires another plugin to override filter X" — out
- "Requires PHP option Y to be enabled" (where Y is a non-default unsafe setting) — out
- "Requires the option to be written outside the Settings API" — out, unless you can name a routine attacker-reachable write path
- "Assumes the WAF is not in front" — out
- "Theoretical / future code change" — out

The attacker controls: HTTP requests, request bodies, cookies they own, files they upload, posts/comments/forms they submit. They do NOT control: server config, admin actions, other plugins' behaviour, or non-default WordPress settings.

If a precondition gates the bug behind something the victim has to do or misconfigure, drop the hypothesis. The downstream triage stage applies the Wordfence scope filter and rejects these anyway — raising them just inflates the hypothesis count and slows triage.

## Self-check before emitting

For each hypothesis, before adding it to your output array:
1. Re-read the source at `file:line` ±15 lines from `code_slices`.
2. Confirm the function/expression you cited as the sink actually appears there.
3. Confirm the upstream guard you claim is absent (no nonce, no capability check) really is absent — search the same code slice for `current_user_can`, `wp_verify_nonce`, `check_ajax_referer`, `permission_callback`. If present, either drop the hypothesis or downgrade confidence and explain why the guard is bypassable.
4. Confirm the precondition is attacker-reachable per the discipline above.

If any check fails, do not emit. The verifier's bar is "the literal `sink_code` appears at the cited line and there is no obvious upstream guard the specialist missed" — meet that bar yourself before emitting.

## Diff hint (optional)

If the input contains a `diff_summary` field, it lists files and changes
between the version being scanned and an earlier version. Treat this as a
prior, not a constraint: bugs that the developer touched recently are more
likely to be incompletely fixed or freshly introduced. Pay extra attention
to the files and line ranges named there. Do not skip files outside the
diff — full coverage is still required — but raise confidence by one tier
on hypotheses that land inside diff-marked regions, and explain in
`reasoning` why the change looks relevant.

If `diff_summary` is absent, ignore this section.
