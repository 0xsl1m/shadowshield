# Security Policy

## Two very different kinds of "security issue"

ShadowShield is a security tool, so please route reports correctly:

### 🟢 New attack techniques ShadowShield should detect → **open a public issue**

If you've found a prompt-injection / jailbreak / exfiltration technique that
ShadowShield *fails to catch*, that is not a vulnerability in ShadowShield — it's a
gap in coverage the whole community benefits from fixing in the open. Please:

1. Open a public issue using the **"Attack pattern / bypass"** template.
2. Include a minimal reproduction string and the expected category.
3. Even better — open a PR adding a signature + a regression test.

### 🔴 Vulnerabilities **in ShadowShield itself** → **report privately**

Examples: a way to silently disable a detector, a ReDoS in a pattern that hangs
the scanner, a path that leaks a secret into the audit log despite redaction, or a
bypass of the fail-closed guarantees. Please **do not** open a public issue.
Report privately via **GitHub Security Advisories**:

> Repository **Security** tab → **Report a vulnerability** (Private Vulnerability
> Reporting). This opens a private channel visible only to you and the maintainers.

Include a description, reproduction steps, affected versions, and impact. We aim to
acknowledge within **72 hours** and to ship a fix or mitigation within **30 days**
for confirmed high-severity issues, coordinating disclosure with you.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Scope reminder

ShadowShield is a strong layered **filter**, not a guarantee. It is one control in
a defense-in-depth strategy (least-privilege tools, human-in-the-loop on
high-impact actions, output validation). Reports that amount to "a sufficiently
novel prompt got through" are coverage gaps (public), not framework vulnerabilities
(private) — though we want to hear about both.
