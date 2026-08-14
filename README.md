# DOMAINSTATE V1

**Domain → current registration state from authoritative RDAP.**

States: `REGISTERED`, `UNREGISTERED`, `EXPIRING`, `HOLD`, `REDEMPTION`, `PENDING_DELETE`, `UNKNOWN`.

`UNREGISTERED` requires an authoritative RDAP HTTP 404. Rate limits, failures, unsupported TLDs, malformed responses, and ambiguous evidence return `UNKNOWN`.

Endpoints: `/health`, `/docs`, `/play?domain=example.com`, `/v1/domain/:domain`, `/mcp`, `/openapi.json`, `/sources`, `/v1/activity`.

MCP tool: `inspect_domain_state`.

Data: IANA RDAP DNS bootstrap + authoritative registry/registrar RDAP only. No WHOIS scraping, registrant PII enrichment, historical WHOIS, or threat scoring.

Cache defaults: IANA bootstrap 6h; positive domain 5m; authoritative 404 1m; ambiguous failure 15s.

Stranger Verification: `X-Domainstate-Test: 1`, `X-Tollbooth-Internal: 1`, known validators, health checks, uptime traffic, and dashboard polling are excluded. Outside core calls begin `UNKNOWN_MACHINE` and do not automatically count as verified strangers.

```bash
npm test
npm start
```
