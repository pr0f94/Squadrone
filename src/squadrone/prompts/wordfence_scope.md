# Wordfence Intelligence Bug Bounty scope

Source: https://www.wordfence.com/threat-intel/bug-bounty-program/terms-and-conditions/
Checked: 2026-08-24

Use this only for disclosure routing after technical validity has been decided.
It must not turn a source-code false positive into a vulnerability or reject a
real vulnerability from the technical record.

## Asset eligibility

- High-threat classes need at least 25 active installs: arbitrary PHP file
  upload/read/deletion, arbitrary options update, RCE, authentication bypass to
  Administrator, or privilege escalation to Administrator.
- Stored XSS and SQL injection need at least 500 active installs.
- Other eligible classes need at least 50,000 installs for a Standard
  researcher, 10,000 for Resourceful, or 500 for 1337.
- WordPress Core; Automattic, Facebook, Google, SiteGround, and Yoast products;
  closed components; and remote vendor services are excluded.
- Targets with 25-999 installs in the special low-install routes must be in the
  WordPress.org repository. Premium components need at least 1,000 installs.

Plugin selection is responsible for these asset checks. Do not infer install
counts from source code.

## Eligible technical outcomes

The current explicit examples are stored/reflected XSS, arbitrary content or
file deletion, SQL injection, arbitrary file upload/read, LFI/RFI, directory
traversal, privilege escalation, authentication bypass, RCE/code injection,
sensitive information disclosure, PHP object injection with a usable gadget,
and intentional backdoors. The issue must have considerable C/I/A impact and be
exploitable by an unauthenticated, Subscriber, or Customer attacker.

## Automatic exclusions

- Contributor, Author, Editor, Shop Manager, Administrator, `unfiltered_html`,
  or another non-default/mid/high role is required.
- Business-only payment, pricing, coupon, order, or revenue impact without a
  direct security consequence.
- Any DoS, limited file upload, CSRF, generic missing authorization, IDOR, basic
  information exposure, SSRF, open redirect, or PHP object injection without a
  usable gadget.
- Vulnerable dependency code without an exploit through this plugin.
- Self-XSS, HTML/CSS/CSV injection, header-only reflected XSS, safe-file upload,
  notice dismissal, public counters, rate limiting, 2FA bypass, tabnabbing, or
  intentional role-limited functionality.
- Non-default unsafe configuration, explicit admin capability grants, EOL
  software, local server access, debug mode, or an external vulnerable product
  is required.
- CVSS v3.1 below 4.0 without a demonstrated route to greater impact.

The report must use a working exploit, the lowest proven attacker role, and the
actual confirmed CIA outcome. A nonce omission or request primitive alone is
not a security impact.
