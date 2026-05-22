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
- `wp_kses_post($html)` strips `<script>`, `<iframe>`, event handlers, `javascript:`
  URLs, but **PRESERVES `<a target="_blank" rel="opener">` verbatim**. This is the
  reverse-tabnabbing primitive — flag any sink that uses `wp_kses_post()` as the
  only sanitiser for user-supplied HTML.
- `sanitize_text_field` strips tags + line breaks but keeps `=()`, quotes, etc.
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

## Object injection / unserialize

- `maybe_unserialize($x)` runs `unserialize` only if `is_serialized($x)` returns true.
  Both reach `unserialize` if the bytes look serialized.
- For a POI to be exploitable, the bytes feeding into `unserialize` must be
  attacker-controlled. If they come from a `wp_options` key written only by
  internal `update_option` calls with sanitized data, the bug is **chained** —
  flag explicitly, don't claim direct exploit.

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
