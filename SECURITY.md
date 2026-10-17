# Security Policy

## Supported versions

Only the latest commit on `master` is supported. This repository targets Final Layer chain ID
`20261012` (the bsc-geth based chain). The earlier java-tron based Final Layer network is retired
and its code is not supported.

## Scope

Key generation and derivation, the encrypted vault, transaction and message signing, the dApp provider and approval flow (`extension/`, `src/`, `web-src/`). Of most interest: key or seed disclosure, signing without user approval, cross-site provider abuse, and weak vault encryption.

## Audit reports

| Scope | Date | Auditor | Report |
| --- | --- | --- | --- |
| fl-wallet | none yet | | No third-party audit has been completed. |

Reports will be published in `docs/audits/` as `YYYY-MM-DD_<scope>_<auditor>.pdf`.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:
**Security → Report a vulnerability** on this repository. Include the affected commit, a
description, and a reproduction.
