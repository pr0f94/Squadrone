# Patchstack Bug Bounty scope

Source: https://patchstack.com/articles/bug-bounty-guidelines-rules/
Checked: 2026-08-24

Use this only for disclosure routing after technical validity has been decided.

## Asset and attacker requirements

- Target the latest publicly distributed, unmodified release. Its most recent
  release must be no older than three years.
- The standard program expects at least 1,000 active installs.
- Premium reports require the original archive.
- The standard program accepts unauthenticated, Subscriber, Customer, or a
  closely equivalent built-in custom role. Author, Editor, Administrator, Shop
  Manager, and explicitly granted custom roles are excluded.
- Patchstack mVDP targets are the exception: Contributor and sub-1,000-install
  reports may be accepted when they have measurable security impact, but may
  receive no XP. Do not assume a component is in mVDP without metadata.

There is no blanket CVSS 6.5 minimum. CVSS v3.1 base metrics are used, while the
specific low-impact and complexity exclusions below determine eligibility.

## Accepted classes and conditions

- SQL injection and RCE/arbitrary code execution.
- XSS that is reflected with JavaScript execution or stored with site-wide
  impact.
- Arbitrary file upload/deletion/download and LFI/RFI with full control over the
  required path and extension.
- PHP object injection.
- Arbitrary WordPress setting changes with significant site impact.
- Privilege escalation to Contributor or higher.
- Broken access control exposing significant objects such as password hashes,
  backup/SQL files, or secrets whose impact is demonstrated.
- IDOR only with significant security impact; PII alone and attachment, ticket,
  event, order, or appointment interactions are excluded.
- CSRF only when it produces an accepted write-related outcome.

## Automatic exclusions

- Attack Complexity High, unrealistic/non-guessable identifiers, or
  configuration explicitly granted by a privileged user.
- Subscriber-or-higher issues with only minor Low CIA effects, and
  unauthenticated issues with exactly one Low CIA effect.
- Contributor-or-higher stored XSS, HTML/CSS/CSV injection, open redirect,
  rate-limit issues, low-role registration, and ordinary 2FA bypass.
- Multi-step CSRF or CSRF without arbitrary file operation, privilege
  escalation, RCE, or a settings change leading to wider compromise.
- Non-arbitrary LFI/upload, constrained paths without working traversal, and
  legacy-extension-only upload claims.
- Blind SSRF without concrete impact, most race conditions below 7.1, or DoS
  without portable site-wide High availability impact.
- Expected functionality, cosmetic state, cache clearing, data reordering,
  cron triggering, insignificant disclosure, or untested/modified software.

The report must provide reproducible raw requests and a clean-state exploit.
HTTP 200, reflection, a blind callback, or a model-written `SUCCESS` line is not
proof of a vulnerability or its CIA impact.
