# Wordfence Intelligence Bug Bounty — Scope Reference

Source: https://www.wordfence.com/threat-intel/bug-bounty-program/#scope
Snapshot date: 2026-05-03

Use this document to decide whether a hypothesis or confirmed finding is worth pursuing for a Wordfence Intelligence submission. A finding that fails any "out-of-scope" rule below will be auto-rejected by Wordfence triage and is not worth the budget to verify or report.

---

## Asset eligibility (plugin-level)

Plugin must meet an active-install threshold that depends on bug class and researcher tier.

**High Threat Vulnerabilities** (≥25 active installs; 25–999 must be in WP.org repo):
- Arbitrary PHP File Upload or Read
- Arbitrary PHP File Deletion
- Arbitrary Options Update
- Remote Code Execution
- Authentication Bypass to Admin
- Privilege Escalation to Admin

**Common and Dangerous Vulnerabilities** (≥500 active installs; 500–999 must be in WP.org repo):
- Stored Cross-Site Scripting
- SQL Injection

**All Other Vulnerabilities** (threshold by tier):
- Standard Researchers: ≥50,000 active installs
- Resourceful Researchers: ≥10,000 active installs
- 1337 Researchers: ≥500 active installs

Default assumption for our pipeline: Standard tier (≥50,000 installs) unless overridden.

**Out-of-scope assets:** WordPress Core, Automattic, Facebook, Google, Siteground, Yoast products. Plugins/themes closed to downloads at submission time. Web services not run locally (vendor APIs).

---

## Explicitly in-scope vulnerability classes

Must NOT require PR:H (Administrator, Editor, Shop Manager, or any role with `unfiltered_html`).

- Stored Cross-Site Scripting
- Reflected Cross-Site Scripting
- Cross-Site Request Forgery (with considerable impact)
- Missing Authorization (with considerable impact)
- Arbitrary Content Deletion
- SQL Injection
- Insecure Direct Object Reference
- Arbitrary File Upload
- Arbitrary File Download/Read
- Arbitrary File Deletion
- Local File Include / Remote File Include
- Directory Traversal
- Privilege Escalation to Admin
- Privilege Escalation to Non-Admin
- Authentication Bypass to Admin
- Authentication Bypass to Non-Admin
- Remote Code Execution / Code Injection
- Information Disclosure
- Server-Side Request Forgery
- PHP Object Injection
- Intentional Backdoors

---

## Explicitly out-of-scope vulnerability classes (auto-reject)

- DoS without considerable demonstrable impact
- Vulnerable dependencies not verifiably exploitable in the plugin
- **Anything requiring PR:H to exploit** (Admin/Editor/Shop Manager/unfiltered_html roles)
- Open Redirect
- Vulnerabilities dependent on race conditions not easily replicable
- Cache Poisoning without considerable demonstrable impact
- SSRF via DNS Rebinding when wp_safe_remote_* / wp_http_validate_url() is used
- API Key Updates/Overwrites/Reads
- Vulns only exploitable when an admin explicitly grants access to lower role (where likelihood is minimal)
- Vulns requiring excessive brute force (case-by-case)
- Private/Hidden/Draft/Pending/Password-Protected post access

## Common False Positives (auto-reject by Wordfence triage)

### Low-impact / theoretical
- Theoretical vulnerabilities
- Username enumeration
- Missing HTTP security headers
- Clickjacking
- Full path disclosure
- Coupon code exposure
- Wishlist updates
- Google Maps API key access
- Endpoints lacking rate limiting (rate limiting is a server-side control)
- **Any CVSS 3.1 < 4.0 that cannot be leveraged to higher impact**

### Injection / client-side (non-exploitable)
- CSV Injection
- CSS Injection
- HTML Injection
- Self-XSS (payload not stored, only rendered on initial action)
- Reflected XSS via headers
- XSS via SVG file uploads
- File uploads with embedded client-side scripts/macros (XSS in PDFs)
- Malicious content stored in safe file types (PHP code in .jpg)
- Double-extension upload attacks (.php.png)
- Safe filetype uploads (.jpg, .png) where intentional

### Auth/access control (expected behaviour)
- IP Spoofing
- CAPTCHA bypasses
- CORS issues
- Tabnabbing
- TOCTOU
- **Dismissing notices via CSRF or missing authorization** ⚠
- CSRF on unauthenticated forms with no sensitive actions
- CSRF on read-only actions
- **Missing authorization where a valid nonce protects the action** ⚠
- **Missing authorization where the nonce is not exposed to lower-privileged users** ⚠
- Adequately secured access keys/tokens used for authorization
- Arbitrary shortcode execution by Contributor+
- High-level (Admin/Editor/Shop Manager) XSS requiring unfiltered_html
- Intentional admin-only functionality (PHP snippet plugins, tracking script insertion)
- Intentional functionality with appropriately limited scope
- User registration bypass when intentionally enabled and doesn't escalate
- Unlimited voting/liking/counting
- 2FA bypasses
- **Missing authorization without consequential C/I/A impact** ⚠

### Environmental / configuration
- Vulns only exploitable on EOL software (PHP, MySQL, Apache, Nginx, OpenSSL)
- SQL injection requiring wp_magic_quotes disabled
- Vulns requiring local server access
- Vulns requiring unsafe PHP config (allow_url_fopen)
- Plaintext secrets that can't be exploited via another vuln
- Uploaded files in publicly accessible directories where exposure doesn't compromise the site
- Vulnerable dependencies not exploitable in this plugin/theme
- Information exposed when WP_DEBUG enabled
- Vulns dependent on admin misconfiguration
- Vulns affecting only outdated browsers (>2 stable versions behind)

---

## Decision rubric for our pipeline

Given a hypothesis (pre-verify) or finding (post-verify), reject as out-of-scope if ANY apply:

1. **PR:H required** — sink is reachable only by Administrator/Editor/Shop Manager/role with unfiltered_html, with no path from a lower role.
2. **Plugin install count** below the tier threshold for the bug class.
3. **Asset on out-of-scope vendor list** (Automattic, Yoast, etc.).
4. **Notice-dismissal handler** — entry point is a "dismiss notice" / "hide notice" / similar UX-only action.
5. **Valid nonce protects the action** AND the nonce is not exposed to a lower-privileged role than the intended one.
6. **Missing-authz finding with no demonstrated C/I/A consequence** — e.g. ability to write a constrained value to a constrained location, with no security-load-bearing target identified.
7. **Open Redirect**, **Cache Poisoning without impact**, **Self-XSS**, **CSV/CSS/HTML injection**, **CSRF on read-only actions** — drop on sight.
8. **Requires EOL PHP version** (PHP < 7.0 etc.) for the bypass to work.
9. **Requires admin to misconfigure** the plugin or another component.
10. **CVSS 3.1 estimate < 4.0** with no escalation path identified.

If none apply, the finding is potentially in-scope. Note: "in-scope" is necessary but not sufficient — Wordfence triage may still reject for other reasons.
