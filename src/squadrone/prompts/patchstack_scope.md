# Patchstack Bug Bounty Scope

**Companion to `wordfence_scope.md`.** Patchstack is the second bounty program we submit to. Use this when triaging whether a finding is bountyable through Patchstack vs Wordfence vs both.

A finding must satisfy ALL the in-scope criteria AND avoid every out-of-scope rejection reason below.

---

## In scope

- WordPress core, plugins, and themes that are publicly distributed through WordPress.org, Envato, GitHub, or a similarly recognised repository.
- Vulnerabilities with a clear, measurable security impact and a **CVSS v3.1 base score of 6.5 or higher**.
- Components with at least **1,000 active installs**, OR **100+ active installs with CVSS 8.5+** AND exploitable as **Unauthenticated, Subscriber, or Customer**.
- Component must have had a release within the last 3 years and the report must target the latest version.
- For premium components, attach the original, unmodified archive so Patchstack can validate.
- Custom roles must have capabilities equivalent to Subscriber or Customer. Roles that exceed those capabilities are out of scope.

---

## Out of scope — common rejection reasons

### Configuration & expected functionality
- Vulnerabilities that only exist because a high-privilege user explicitly configured the component that way.
- Vulnerabilities where the plugin's own Permissions UI lets administrators grant a capability to a lower-priv role (Author/Editor/Contributor/Subscriber), exposing the issue to that role.
- Expected functionality is not a vulnerability — e.g. a contact form that allows uploads does not qualify as DoS just because someone could submit large quantities of entries.
- Authenticated shortcode issues without sensitive data disclosure.

### Scoring & identifier requirements
- Any report involving **Attack Complexity: High (AC:H)**.
- Subscriber-or-higher vulns leading to minor/insignificant data leakage, minor data modification, or minor availability impact (CVSS 5.4 with two CIA at L, 6.3 with three at L).
- Unauthenticated vulns with only one CIA at Low impact (CVSS 5.3).
- Actions that require a non-guessable or unrealistic identifier to be impactful — e.g. cancelling a subscription that requires knowing a long, randomly-generated subscription hash.
- Re-ordering data, clearing cache, or manually triggering cronjobs / scheduled tasks.

### Submission requirements
- Multiple findings of the same vulnerability type must be consolidated into a single report.
- Vendor or developer self-submissions — accepted for disclosure but not eligible for bounties.
- Incomplete, inaccurate, or unverifiable information, or invalid vulnerability claims.
- Unrealistic pre-requisites or exploitation scenarios.
- Closed, inaccessible, or non-publicly-distributed components, or reports based on non-standard user roles.
- CSV injection, CAPTCHA bypasses, and IP spoofing.

### Information disclosure
- Full path disclosure.
- Private or draft post, page, or content disclosure — unless the post type can leak extremely sensitive data.
- Enumeration that does not expose significant information (only confidentiality at Low impact).
- API key leakage that does not result in significant impact.

### XSS, HTML & CSS injection
- Contributor-level (or higher) stored XSS.
- HTML-only injection without JavaScript execution — e.g. injection into emails or rendered output where script execution is not possible.
- CSS injection.

### Authentication & access control
- 2FA bypass — typically Attack Complexity: High since you need the password to exploit.
- Lack of brute-force protection / rate-limiting (e.g. login). Excludes the login TOTP feature and sequential filenames.
- Account creation or registration with a low-privilege role (below Contributor).
- Arbitrary user registration unless it leads to a Contributor-or-higher account.

### CSRF
- Multi-step CSRF exploits — e.g. CSRF to an admin action that then requires the admin to perform a second action to trigger the impact.
- CSRF must lead to one of: arbitrary file upload or deletion, privilege escalation (e.g. via an options change), RCE with a working PoC, or a settings change that leads to wider compromise.
- CSRF or access-control issues that only affect admin-notice dismissal, or IP bypass for non-critical actions.

### File operations
- Non-arbitrary LFI — only accepted with full control over the path AND extension.
- Constrained-path LFI without a working directory-traversal exploit. Windows-specific bypass techniques are excluded.
- Non-arbitrary file uploads involving legacy extensions such as `.phtml`.

### Open redirect
- Open redirect is inherently out of scope.

### DoS, race conditions & SSRF
- Most race conditions (below CVSS 7.1).
- DoS, unless it has high availability impact and is demonstrable on any environment.
- Blind SSRF — must demonstrate concrete impact.
- AI feature token exhaustion.

---

## Practical implications for triage

- **Install-count floor is far lower than Wordfence Standard tier (1,000 vs 50,000 for "all other" classes).** A finding rejected by Wordfence due to install count may still qualify for Patchstack.
- **CVSS gate is strict (≥6.5).** Low-impact bugs that Wordfence accepts as "Special Note / Resourceful tier credit" will be rejected outright by Patchstack. Compute CVSS first; if <6.5, don't bother submitting.
- **Plugins that direct security reports to Patchstack VDP are now in-scope candidates** for our scanning — they were previously rejected at the plugin-selection stage. The disclosure channel is the right destination, not a disqualifier.
- **For dual-eligible findings (≥6.5 CVSS, ≥50k installs, no Patchstack VDP redirect)**: prefer Wordfence (typically higher payouts), but Patchstack is the fallback if Wordfence rejects on scope/dedup grounds.
- **Subscriber+ stored XSS** is in-scope here (Patchstack only excludes Contributor+); Wordfence is similar but use higher CVSS thresholds for Patchstack to avoid the 6.5 floor.
