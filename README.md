# PR Secret & API Key Leak Gate

> **Category:** Security | **Pricing:** $29/mo per organization | **Vendor:** Ricardo Vieira Forge Cloud

## Why Use This Action?

Developers accidentally commit AWS keys, Stripe live tokens, GitHub PATs, and PEM private keys in PRs; native secret scanning only alerts post-push on public/GHAS repos.

**Competitive Edge:** GitHub Advanced Security costs $49/committer/mo; open-source scanners lack zero-config PR annotations + Step Summary + org-wide $29/mo flat pricing.

## Quick Start (Copy-Paste Workflow)

```yaml
name: PR Secret Leak Gate
on:
  pull_request:
    branches: [main, master]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run PR Secret & API Key Leak Gate
        uses: ricardovieiraforge/pr-secret-leak-gate@v1
        with:
          scan-path: '.'
          entropy-threshold: '4.3'
          fail-on-find: 'true'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `scan-path` | Directory to scan for leaked secrets | `False` | `.` |
| `entropy-threshold` | Minimum Shannon entropy for high-entropy token alerts | `False` | `4.3` |
| `fail-on-find` | Fail the workflow if secrets are detected | `False` | `true` |
| `ignore-paths` | Comma-separated path substrings to ignore | `False` | `node_modules,.git,dist,coverage` |

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of potential secret leaks detected |
| `passed` | true if no secrets found or fail-on-find is false |

## Local Verification

```bash
node --check src/index.js
node src/index.js --self-test
```

## License

MIT — Built by Ricardo Vieira Forge Cloud (souza@usa.com).
