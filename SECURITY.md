# Sentinal Security Policy

## Supported Versions

Sentinel follows **semantic versioning**. Security patches are backported to the
latest minor release of each major version.

| Version | Supported          |
| ------- | ------------------ |
| 0.x     | ✅ Active development |

## Reporting a Vulnerability

Sentinel is a security scanning tool, so its own security posture matters.
If you discover a security vulnerability in Sentinel itself, please report it
privately — **do not file a public GitHub issue**.

### How to Report

Please report vulnerabilities through GitHub's built-in **Private vulnerability reporting** feature:

[https://github.com/your-org/sentinel/security/advisories/new](https://github.com/your-org/sentinel/security/advisories/new)

This creates a private draft advisory that only the repository maintainers can see.
No account setup required beyond your existing GitHub account.

> **Note:** Private vulnerability reporting must be enabled in the repository settings (under **Settings → Code security & analysis**).

### What to Expect

1. **Acknowledgment** — You'll receive a reply within **48 hours** confirming receipt
2. **Investigation** — We'll assess the severity and impact within **5 business days**
3. **Fix & Release** — A patch will be developed, reviewed, and released. Timeline depends on severity:
   - **Critical** — Patch within 7 days
   - **High** — Patch within 14 days
   - **Medium/Low** — Patch within 30 days
4. **Disclosure** — After the fix is released, we'll publish a security advisory on GitHub

### Scope

The following are **in scope** for security reports:

- Remote code execution or command injection via Sentinel
- Credential leakage through Sentinel's output or error messages
- Path traversal allowing access to files outside the target repository
- Denial of service via crafted inputs
- Bypass of Sentinel's detection capabilities (false negatives)

The following are **out of scope**:

- Vulnerabilities in repositories *scanned by* Sentinel (that's Sentinel's job to find!)
- Theoretical attacks requiring physical access or man-in-the-middle positioning
- Features explicitly documented as experimental or for demonstration purposes


## Preferred Languages

We prefer reports in **English**. Reports in other languages may experience
delays in triage.

## Recognition

We believe in honoring security researchers who help us improve Sentinel.
With your permission, we'll:

- Add your name to our Security Hall of Fame *(coming soon)*
- Credit you in the published security advisory
- Thank you publicly on our social channels

## Disclosure Policy

- **Private disclosure**: Vulnerabilities are reported and fixed privately
- **Coordinated disclosure**: We work with the reporter to set a disclosure date
- **Public disclosure**: A GitHub Security Advisory is published after the fix is released

We aim for a maximum **90-day disclosure timeline** from initial report to public
advisory, though critical issues may be disclosed sooner once a fix is available.

---

*This policy is adapted from best practices established by [GitHub Security Lab](https://securitylab.github.com/)
and the [Coordinated Vulnerability Disclosure (CVD)](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure) framework.*
