# WordPress idioms — facts you must NOT recall from training

These are factual properties of WordPress that have been consistently
mis-recalled in past pipeline runs. When ANY of your reasoning rests on a claim
about a WP function's behaviour, verify it against actual WP source via tool
calls. The list below is a defensive reference, not exhaustive.

## Escaping helpers

- `esc_url($url)` **DOES** percent-encode and entity-encode quotes. Single
  quotes become `&#039;`, double quotes become `&quot;`. So `esc_url` is safe
  inside both single- and double-quoted HTML attributes for the quote-breakout
  attack class. (Past hallucination: "esc_url doesn't encode single quotes".)
- `esc_attr` HTML-encodes `&"<>'` for attribute context. Safe inside any
  quoted attribute.
- `esc_html` HTML-encodes `&"<>` (NOT single quotes by default before WP 5.5;
  current WP encodes `'` to `&#039;` too).
- `esc_js` escapes for inline JS string context only — does NOT escape for
  attribute or HTML context. A common mistake is `onclick="<?php echo esc_js($x); ?>"`
  which still allows attribute breakout via `&quot;` decoding.
- `wp_kses_post($html)` strips `<script>`, `<iframe>`, event handlers, and
  `javascript:` URLs. Preserved links or markup are not XSS unless JavaScript
  execution is demonstrated in a supported browser.
- `sanitize_text_field` strips tags + line breaks but keeps `=()`, quotes, etc.
  Its core `_sanitize_text_fields()` implementation has no embedded-NUL
  rejection: it checks UTF-8, handles `<`/tags, collapses selected whitespace,
  trims the ends, and removes literal `%HH` substrings. For ordinary
  form-encoded input, PHP decodes `%HH` before populating `$_POST`, so an encoded
  NUL arrives as an embedded raw NUL before `wp_unslash()` and text cleaning.
  Do not treat this sanitizer alone as proof that PHP serialized protected or
  private property names cannot survive; trace the actual transport and every
  subsequent transform, and verify that serialized byte lengths still match.
- `sanitize_file_name` aggressively strips `<>"|?*\:` — filenames cannot carry
  HTML-attribute breakout payloads through this filter.

## Nonces

- `wp_create_nonce($action)` derives the nonce from `$action`, `wp_nonce_tick()`,
  the current `user_id`, AND `wp_get_session_token()`. **Nonces are user-bound:**
  user A's `wp_create_nonce('foo')` does NOT match user B's `wp_create_nonce('foo')`.
  Forging admin's nonce by calling `wp_create_nonce` as a Subscriber DOES NOT WORK.
- A nonce is exploitable by a Subscriber only when the Subscriber can scrape it
  from a server-rendered page where it's emitted (`wp_localize_script`,
  `wp_nonce_field`, `data-nonce` attribute, etc.). Find the emission site to
  prove reachability — don't assert it from training data.
- `update-options` is the WordPress core Settings API action. Its nonce is
  emitted by `settings_fields()` on admin settings forms — admin-only by default
  unless a third-party plugin emits it on a Subscriber-reachable surface.
- `wp_rest` is the REST API nonce. WP enqueues `wpApiSettings.nonce` via
  `wp-api-fetch` for admin contexts; check whether the enqueue runs for
  Subscriber-reachable pages on this specific plugin (depends on `wp_enqueue_script`
  call site).

## AJAX entry-point semantics

- `add_action('wp_ajax_<X>', $cb)` requires the user to be **logged in** (any role,
  including Subscriber). It does NOT enforce admin or any capability — that's the
  handler's responsibility.
- `add_action('wp_ajax_nopriv_<X>', $cb)` is **unauthenticated** — anyone can call.
- WordPress does NOT have a `wp_verify_ajax_request()` function; do not invent it.
- `check_ajax_referer($action, $field)` only verifies the nonce — it does NOT
  check capabilities. A handler with only `check_ajax_referer` is `nonce_only`
  gated.
- `current_user_can($cap)` checks the named capability against the current user.
  `'manage_options'` ≈ admin. Plugin-specific helpers (e.g. `User::Access('manage')`
  in wp-statistics) often wrap this with their own naming.

## Database

- `$wpdb->prepare($sql, ...$args)` with `%s`/`%d`/`%f` placeholders is correctly
  parameterised — flag the call as SQLi only if the prepared string is later
  re-concatenated with attacker-controlled bytes.
- `$wpdb->insert/update/delete` with `format` arrays is parameterised.
- `dbDelta` is for schema migrations, not user data — not an SQLi sink.

## User metadata and protected attributes

- `update_user_meta($user_id, $key, $value)` performs the requested metadata
  write; it does not authorize an attacker-controlled `$key`. Trace the key and
  value independently back to the request and require a server-side allowed-key
  set before treating a generic write as safe.
- WordPress role/capability state is stored in a table-prefix-specific
  capabilities user-meta key (commonly `wp_capabilities`). PHP bracket-shaped
  request fields can supply an array value. Writing that protected attribute on
  a current or newly created account can elevate the account; it is not a
  harmless own-object update.
- Validation of a dedicated field such as `role` does not constrain a separate
  request-controlled metadata key. Verify that filtering is applied on the
  exact path to the dynamic write, rather than merely finding a denylist or
  cleaner used by another caller.

## Core Custom Fields post-meta writers

- The standard post-editor Custom Fields path is a possible writer for a
  plugin-read fixed post-meta key even when the plugin's own save handler
  sanitizes that key. Core `edit_post()` and `wp_ajax_add_meta()` can reach
  `add_meta($post_id)`. `add_meta()` casts the post ID, reads the submitted key
  and value, rejects `is_protected_meta()` keys and callers lacking
  `add_post_meta` for that exact post/key, then calls `add_post_meta()`. It does
  not apply a generic text sanitizer or post-content KSES to the value.
  Metadata storage still invokes `sanitize_meta()`, so trace any registration,
  subtype-specific callback, or dynamic sanitizer/filter for the exact key.
- Core's authenticated `wp_ajax_add-meta` dispatch at
  `POST /wp-admin/admin-ajax.php` accepts POST form fields `action=add-meta`,
  `post_id`, `metakeyinput` or `metakeyselect`, `metavalue`, and
  `_ajax_nonce-add-meta`. `wp_ajax_add_meta()` verifies the nonce for action
  `add-meta`, casts and resolves `post_id`, and requires `edit_post` on that
  exact object before calling `add_meta()`; `add_meta()` then requires the
  mapped `add_post_meta` capability for the exact key. The nonce is emitted by
  the post editor's Custom Fields form. A claimed low-privilege path therefore
  must prove the role can edit the exact selected target post and can obtain the
  nonce from a normally reachable Custom Fields form available to that account.
  The nonce-providing form need not belong to the selected target or its post
  subtype. These authorization checks do not apply text sanitization or
  constrain a public key to a plugin-owned post type.
- Because this supplied writer contract is in WordPress core, its exact POST
  fields and calls need not have a plugin `relative/file:line` citation in
  `evidence_summary.source`. Do not fabricate one. This narrow exception still
  requires read-tool evidence for the plugin's fixed-key metadata read,
  shortcode expansion, output context, and assigned coverage item; it does not
  waive source grounding for a plugin-defined or any other external writer.
- This is not proof that every post-meta read is attacker-writable. Require the
  claimed role to pass the exact edit/meta capability for a selected post it
  owns or otherwise may edit, and prove the reader can select that same object.
  Bind the post ID's input type and conversion, post type/status and ownership,
  effective key and publicness, value transformation, and final output context.
  A leading-underscore/protected key, a server-bound object, or an effective
  key/post-type restriction can make the core Custom Fields path irrelevant.
- Save-time KSES on a low-privilege user's `post_content` does not automatically
  filter HTML returned later by a shortcode callback. When the saved content
  merely invokes a shortcode and plugin code generates output from a separate
  public meta value, inspect the callback's final context and its own escaping
  or KSES. Do not classify that separate path as ordinary Contributor/Author
  content without tracing it.

## Object injection / unserialize

- `maybe_unserialize($x)` runs `unserialize` only if `is_serialized($x)` returns true.
  Both reach `unserialize` if the bytes look serialized.
- Metadata can be an implicit deserialization boundary even when plugin source
  has no visible `unserialize()` call. A raw low-level database write that puts
  attacker-controlled serialized bytes into a metadata value can later reach
  core deserialization through a high-level metadata read or update, including
  `get_metadata()` with a non-empty metadata key and
  `update_metadata()` handling of the existing value. The verified WordPress
  core contract is: a non-empty-key `get_metadata()` read delegates to
  `get_metadata_raw()`, whose single-value and list branches apply
  `maybe_unserialize()` to stored values; when `$prev_value` is empty,
  `update_metadata()` also calls `get_metadata_raw()` with the non-empty key.
  `maybe_unserialize()` calls unrestricted `unserialize()` when the bytes are
  serialized. A non-null result from the dynamic
  `get_{$meta_type}_metadata` filter short-circuits that cache/key branch, and
  a low-level write may leave an already-populated metadata cache stale. Trace
  both conditions for the exact workflow; do not assume a direct API call alone
  reaches deserialization. This supplied core contract does not require a
  WordPress-core file inside the plugin source tree. Trace the same metadata
  type, object ID, and key across both plugin operations.
  That tuple binds the raw write to the later access; the attacker need control
  only the serialized value. A fixed type/key or a server-generated object ID
  does not make the path safe. A definitely non-empty `$prev_value` is relevant
  counterevidence because it skips this old-value comparison path.
- After finding a raw insert paired with a same-model metadata read or update,
  first trace the mapped value to external ingress and prove the later operation
  runs in the same workflow. Defer unrelated tables, migrations, and gadget
  inspection until this source-to-implicit-sink path is established.
- A generic text sanitizer or recursive text-cleaning wrapper is not by itself a
  PHP-serialization allowlist. Prove that its exact output cannot satisfy
  `is_serialized()`; do not infer that from tag/whitespace cleaning. Also check
  alternate current and legacy public callers that assign the same raw-written
  model property.
- Normal `add_metadata()`/`update_metadata()` and object-specific metadata API
  writes serialize non-scalar values before storage. Those API writes alone do
  not establish raw attacker-controlled serialized-byte ingress.
- For a POI to be exploitable, the bytes feeding into `unserialize` must be
  attacker-controlled. If they come from a `wp_options` key written only by
  internal `update_option` calls with sanitized data, the bug is **chained** —
  flag explicitly, don't claim direct exploit.
- A natural-gadget proof recipe is not serialized-payload authoring. The safe
  v1 form is one shipped object triggered by `__wakeup` or `__destruct`, with
  exact complete source anchors, one parent-supplied ephemeral path, and only a
  source-reviewed `unlink` file-delete effect. Every additional unlink must be
  controlled by a complete reviewed condition over one parent-derived opaque
  generation ID and source-bound directory/basename literals. A local-path
  helper is usable only when its complete body routes HTTP(S) away, rejects
  every other scheme, and reaches builtin `file_exists` on the same no-scheme
  argument. The capability/property/iteration value must remain immutable to
  the sink (no assignment, indexed write, unset, alias, or by-reference helper),
  including foreach/destructuring rebinding and by-reference returns,
  and no unreviewed magic hook besides `__construct` may accompany the selected
  trigger. Any class-static write must be only a source-bound empty native array
  read once and set to boolean `true` once at the opaque-ID key.
  Prefix-constrained deletion is not proof of a direct
  attacker-selected path. Raw paths/serialization, nested objects/references,
  callbacks, dynamic helpers, unresolved calls, and other terminal effects are
  outside this bounded contract and must not be approximated.

## File upload

- `wp_handle_upload($file, ['test_form' => false])` still runs WP's intrinsic
  `wp_check_filetype_and_ext` — by default rejects `.php`, `.phtml`, `.html`,
  `.htm`, `.js`, `.htaccess`, etc. Stored XSS via SVG requires SVG to be in
  `upload_mimes` (NOT default; usually added by Safe SVG plugin which also
  sanitizes, or by SVG Support plugin which doesn't).
- A handler hooked on `wp_ajax_nopriv_<X>` for legitimate frontend reasons
  (registration form avatar uploads, etc.) is NOT inherently a missing-authz
  bug — frame as "anonymous file write that doesn't honour `users_can_register=0`"
  or "stored XSS chain via uploaded SVG when SVG enabled" instead.

## When to call read_plugin_file / grep

If you need to claim "X is gated by Y" or "Y is reachable by Subscribers",
verify it by reading source. Examples that demand verification:
- "The nonce action `foo_action` is emitted on a Subscriber-reachable page"
  → grep for `wp_create_nonce('foo_action')` and `wp_localize_script.*foo_action`
- "wp_ajax_X handler has no capability check" → read the handler body
- "esc_url doesn't encode single quotes" → read `wp-includes/formatting.php`
  esc_url + clean_url; do not assert from training
