# Plugin Selection Scope

**MUST be consulted whenever recommending or selecting a WordPress plugin to scan with wpvulnhunt.**

This is distinct from `wordfence_scope.md`, which describes which *bug classes* Wordfence pays bounties for. This document describes which *plugins* are worth investing budget to scan.

A plugin must satisfy ALL hard requirements to be a valid scan target. The quality heuristics influence ranking among valid candidates.

---

## Hard requirements (must all pass)

### 1. Active maintenance
- Last release within the past 6 months on wordpress.org/plugins/&lt;slug&gt;/
- "Tested up to" within 1 major WP version of current
- At least one resolved issue in the last 2 months on the support forum
- Reject if last update >12 months ago, or if the readme says "looking for new maintainer", or if the WP.org page is closed/abandoned.

### 2. Disclosure channel determines submission path (not whether to scan)
We submit to **both Wordfence and Patchstack**. The plugin's disclosure channel determines which program a finding goes to, not whether the plugin is worth scanning.

Check the readme's "How can I report security bugs?" / "Report a security vulnerability" section and tag the candidate:
- **Patchstack VDP** (`https://patchstack.com/database/vdp/...`) → findings submit through Patchstack (consult `patchstack_scope.md` — note CVSS ≥6.5 floor)
- **Vendor program** (HackerOne / Bugcrowd / Intigriti / vendor bounty like WPMU DEV) → **reject** the plugin; we don't compete with vendor programs
- **No security section, vendor support email, or wordpress.org support** → findings submit through Wordfence (default channel)

**Reject only if** the plugin uses a non-Patchstack vendor program. Patchstack VDP is now a valid destination, not a disqualifier.

### 3. Vendor must NOT be on Wordfence's out-of-scope list
Reject any plugin authored by:
- Automattic (and `a11n` / `wpcom` profiles)
- Yoast
- Facebook
- Google
- Siteground

### 4. Install count must qualify for at least one of the two programs

**Wordfence** (cross-reference `wordfence_scope.md`, defaults to **Standard Researcher tier**):
- High Threat bugs (file upload/read/delete to RCE, options update, RCE, auth bypass to admin, privesc to admin) — min 25 installs
- Stored XSS or SQLi — min 500 installs
- All other bug classes (missing-authz, IDOR, SSRF, CSRF, info disclosure, reflected XSS, deserialization, etc.) — **min 50,000 installs** at Standard tier
  - Resourceful tier: drops to 10,000
  - 1337 tier: drops to 500

**Patchstack** (cross-reference `patchstack_scope.md`):
- Min **1,000 active installs** (or 100+ for CVSS 8.5+ unauth/Subscriber/Customer)
- All findings need **CVSS ≥ 6.5**

**Evaluate each program independently — do NOT mix the rule sets.** A plugin is a valid scan target if it satisfies the install-count requirements of *at least one* of the two programs. Whether any specific finding from that plugin is bountyable, and through which program, is decided per-finding at the triage stage using each program's full rules. Do not pre-narrow the scan target by guessing which bug classes are likely to be found.

### 5. Plugin must not have been scanned in this project before
Check the runs/ directory for prior intake.json files containing the plugin slug. Don't re-scan unless explicitly asked.

### 6. Plugin must NOT be closed or removed from wordpress.org
The readme will say "This plugin has been closed as of YYYY-MM-DD and is not available for download." Wordfence considers closed plugins out of scope.

---

## Quality heuristics (rank candidates that pass hard requirements)

Higher score = better candidate. These are tie-breakers, not hard requirements.

### Strong positive signals
- **Recent security fixes in the changelog** (e.g. "Fix: XSS in foo block", "Security: Hardened ..."). This means: vendor accepts disclosures, AND there are likely residual issues nearby.
- **Real attack-surface shape**: forms (frontend submission, registration, login, profile), file ops (upload/read/delete), REST endpoints, AJAX handlers, payment integrations, role-based content access, custom database tables, deserialization (`unserialize`, `maybe_unserialize`), URL fetching (`wp_remote_*`).
- **Less mainstream than category leaders**: e.g. an alternative to a popular plugin in the same category often has the same shape but less audit attention.
- **Niche functionality**: classifieds, recipes, events, memberships, directories, file managers — often have unusual data models that lead to overlooked bugs.

### Weak positive signals
- Active issue resolution (>50% of issues resolved in last 2 months)
- Multiple contributors (less likely to have a sole-maintainer mistake pattern)
- WordPress 6.x+ tested

### Negative signals (de-rank but don't disqualify)
- Heavily audited / on Wordfence's "well-known plugins" list (residual bugs are scarce)
- Mainly a UI/styling plugin (low sink density)
- Closed-source premium addons that gate the interesting code
- Vendor with a history of disputing valid disclosures
- Recent vendor security wave just shipped (likely all the obvious bugs are gone, only deeper bugs remain)

### Anti-patterns to avoid
- Plugins with <1,000 installs (below the lowest Patchstack floor; only worth scanning if you're 1337 tier on Wordfence and targeting High Threat / Stored XSS / SQLi specifically)
- Plugins where the only attack surface is admin-only (PR:H bugs are out of scope)
- Plugins that primarily wrap external services (the bugs are usually in the service, not the plugin)

---

## Process to follow when asked to recommend a plugin

1. Generate 2-4 candidate slugs based on the user's stated criteria
2. For each candidate, fetch the wordpress.org plugin page and verify the hard requirements:
   - Last update date
   - Active install count
   - Disclosure channel mentioned in readme
   - Vendor on out-of-scope list?
   - Plugin closed?
3. Drop any candidate that fails a hard requirement; explain why
4. Rank survivors by quality heuristics
5. Recommend the top candidate with caveats made explicit (e.g., "5k installs means only Stored XSS / SQLi / High Threat will be bountyable for Standard tier")
6. Ask the user to confirm before launching

---

## Common candidate categories worth exploring

- **Frontend forms / submissions** (contact, registration, classifieds, job listings, recipe submissions)
- **File operations** (upload plugins, file managers, media organisers, backup tools)
- **REST API surface** (analytics, dashboards, headless CMS plugins)
- **Payment / membership / e-commerce add-ons** (not WooCommerce core; smaller payment processors, member access)
- **Comment systems** (e.g. wpdiscuz)
- **Directory plugins** (business directory, member directory)
- **Custom-field / form-builder plugins** (often have eval/include/serialize issues)
- **Event / booking / appointment plugins** (often have unauth-reachable booking flows)

## Common categories to avoid (low ROI)

- Pure UI / styling plugins (theme switchers, button decorators)
- Admin-only utilities (PHP code editors, snippet runners) — bug class is by design
- Pure read-only display plugins (post grids without filters/forms)
- Plugins that wrap an external service with no local logic
- Plugins under 500 installs (below floor for any tier)
