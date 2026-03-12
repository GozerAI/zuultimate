# Commercial Licensing — zuultimate

This project is dual-licensed:

- **AGPL-3.0** — Free for open-source use with copyleft obligations
- **Commercial License** — Proprietary use without AGPL requirements

## Tiers

| Feature | Community (Free) | Pro ($149/mo) | Enterprise ($499/mo) |
|---------|:---:|:---:|:---:|
| JWT auth, vault, middleware | Yes | Yes | Yes |
| Rate limiting, webhooks, MFA | Yes | Yes | Yes |
| Executive RBAC Matrix | — | Yes | Yes |
| Compliance Reporting | — | Yes | Yes |
| SSO / OIDC | — | Yes | Yes |
| AI Security Gateway | — | — | Yes |
| ToolGuard Pipeline | — | — | Yes |
| Injection Pattern Library | — | — | Yes |
| Red Team Tool | — | — | Yes |
| Security scans/month | — | 10K | 100K |
| Support SLA | Community | 48h email | 4h priority |

## How It Works

- **No license key** — All code runs (AGPL mode).
- **License key set** — Only entitled features unlocked.
- **Server unreachable** — Fail-open.

## Getting a License

Visit **https://1450enterprises.com/pricing** or contact sales@1450enterprises.com.

```bash
export VINZY_LICENSE_KEY="your-key-here"
export VINZY_SERVER="https://api.1450enterprises.com"
```

## Feature Flags

| Flag | Tier | Description |
|------|------|-------------|
| `zul.rbac.matrix` | Pro | Executive RBAC matrix |
| `zul.compliance.reporter` | Pro | Compliance report generation |
| `zul.sso.oidc` | Pro | OIDC/SAML SSO providers |
| `zul.gateway.middleware` | Enterprise | AI Security Gateway middleware |
| `zul.gateway.standalone` | Enterprise | Standalone gateway app |
| `zul.toolguard.pipeline` | Enterprise | Pre/post execution guard |
| `zul.injection.patterns` | Enterprise | Bundled detection patterns |
| `zul.redteam.tool` | Enterprise | Adversarial testing tool |
