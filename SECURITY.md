# Security Policy

This client exists so that you can verify, rather than trust, how Aionda Mail
protects your mailbox. Reports that help us keep that promise are very welcome.

## Supported versions

Security fixes are released for the latest minor version only.

| Version | Supported |
|---|---|
| 0.17.x | ✅ |
| < 0.17 | ❌ — please update (`npx -y @aiondadotcom/mail-mcp-client` always runs the latest) |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub:
[**Report a vulnerability**](https://github.com/AiondaDotCom/aionda-mail-mcp-client/security/advisories/new)

Helpful to include:

- the affected version (`npm ls @aiondadotcom/mail-mcp-client`) and Node.js version,
- what an attacker can achieve (for example: read plaintext, obtain a key, make the client send unencrypted data),
- steps or a proof of concept to reproduce it.

Never include real mailbox content, API keys (`tma_…`, `tmmcp_…`) or vault keys (`tmv_…`) in a report.

## What happens next

1. We confirm that we received your report, usually within a few working days.
2. We investigate and keep you informed about the assessment and the fix.
3. We publish the fix as a new release and a GitHub security advisory, crediting you unless you prefer to stay anonymous.

Please give us a reasonable time to ship a fix before disclosing details publicly.

## Scope

**In scope:** this repository and the npm package `@aiondadotcom/mail-mcp-client`, in particular:

- anything that lets plaintext, the vault master key, private keys, `tmv_…` or API keys leave the user's machine,
- weaknesses in the cryptography (hybrid KEM X25519 + ML-KEM-1024, AES-256-GCM, HKDF key derivation, the `tmv_…` envelope),
- ways for a malicious server or network attacker to make the client accept forged data or downgrade its protection,
- supply-chain issues in the package or its release process.

Security issues in the Aionda Mail service, web app or native apps can be reported the same way, through
[GitHub](https://github.com/AiondaDotCom/aionda-mail-mcp-client/security/advisories/new); we route them to the right team.
Denial-of-service against our servers, spam and social engineering are out of scope.

## Verifying what you install

Every release is built and published from GitHub Actions with an npm provenance attestation recorded in the public Sigstore
transparency log. To check that an installed package was built from this repository:

```bash
npm audit signatures
```

The design, including what this client does **not** prove, is described in
[chapter 26 of the Security Whitepaper](https://mail.aionda.com/?cmd=security).
