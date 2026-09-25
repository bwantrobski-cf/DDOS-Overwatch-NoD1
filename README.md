# DDOS Overwatch (Cloudflare Worker)

This public version has no D1 database binding or storage dependency. Recent DDoS events are loaded from Cloudflare GraphQL.

`DDOS Overwatch` is a Cloudflare Worker with a web UI that can:

- Query Cloudflare GraphQL (`/client/v4/graphql`) through a secure proxy.
- Call Cloudflare REST API endpoints for:
  - Magic Network Monitoring Rules (`/accounts/{account_id}/mnm/rules`)
  - GRE tunnels, IPsec tunnels, routes, and interconnects under `/accounts/{account_id}/magic/*`

The Worker never hard-codes the bearer token. It reads a secret from `API_BEARER`.

## 1) Prerequisites

- Node.js 18+
- A Cloudflare API token with permissions for the endpoints you need
- Wrangler CLI (installed via `npm install`)

## 2) Configure account + secret

Replace the generic `ACCOUNT_ID` placeholder in `wrangler.toml` under `[vars]` with your Cloudflare Account ID. This is the 32-character account identifier shown in the Cloudflare dashboard.

Cloudflare GraphQL names this value `accountTag`, but it is the same Account ID—not a separate setting. The Worker uses `ACCOUNT_ID` for both REST API paths and GraphQL account filters.

Set `API_BEARER` as an encrypted Worker secret. Do not add the token value to `wrangler.toml` or commit it to the repository.

To configure it in the Cloudflare dashboard, open the Worker, go to **Settings → Variables and Secrets**, add `API_BEARER`, select **Secret**, and enter the Cloudflare API token as its value.

Alternatively, set the same Worker secret with Wrangler:

```bash
npx wrangler secret put API_BEARER
```

The Worker receives this binding as `env.API_BEARER`.

For local development only, use `.dev.vars` (do not commit it):

```bash
ACCOUNT_ID=your_cloudflare_account_id
API_BEARER=your_cloudflare_api_token
```

## 3) Run locally

```bash
npm install
npm run dev
```

Open the Wrangler dev URL in your browser.

## 4) Deploy

```bash
npm run deploy
```

## UI tabs

- **Overview**: BGP prefix status, recent DDoS attack events from Cloudflare GraphQL, and tunnel health
- **Analytics (API)**: Magic Transit bandwidth, DDoS GraphQL analytics, and schema explorer
- **Magic Transit**: View and manage BGP prefixes, GRE/IPsec tunnels, CNIs, and routes
- **Network Flow**: View and manage static, dynamic, and sFlow rules
- **FlowtrackD**: Manage Advanced TCP Protection through the account-level DDoS Protection API
  - View and change the global protection status
  - Manage protected or excluded prefixes and Advanced TCP allowlist entries
  - Manage global, regional, and per-data-center SYN flood rules and filters
  - Manage global, regional, and per-data-center out-of-state TCP rules and filters
  - Requires an API token with DDoS Protection Read or Write permissions as appropriate
- **Usage**: Calculate separate ingress and egress P95 throughput from 5-minute tunnel samples
  - Defaults to a 30-day window, with 24-hour and 7-day options
  - Shows each tunnel's nearest-rank P95
  - Shows account totals as the sum of all per-tunnel P95 values
  - Counts missing 5-minute intervals as zero

## API proxy endpoints (Worker internal)

- `POST /api/graphql`
- `GET|POST|PUT /api/mnm/rules`
- `GET|PATCH|DELETE /api/mnm/rules/:ruleId`
- `GET /api/magic/gre_tunnels`
- `GET /api/magic/gre_tunnels/:greTunnelId`
- `GET /api/magic/ipsec_tunnels`
- `GET /api/magic/ipsec_tunnels/:ipsecTunnelId`
- `GET /api/magic/routes`
- `GET /api/magic/routes/:routeId`
- `GET /api/magic/cf_interconnects`
- `GET /api/magic/cf_interconnects/:interconnectId`
- `GET|PATCH /api/ddos-protection/status`
- `GET|POST|DELETE /api/ddos-protection/prefixes`
- `POST /api/ddos-protection/prefixes/bulk`
- `GET|PATCH|DELETE /api/ddos-protection/prefixes/:prefixId`
- `GET|POST|DELETE /api/ddos-protection/allowlist`
- `GET|PATCH|DELETE /api/ddos-protection/allowlist/:prefixId`
- `GET|POST|DELETE /api/ddos-protection/syn/{rules|filters}`
- `GET|PATCH|DELETE /api/ddos-protection/syn/{rules|filters}/:itemId`
- `GET|POST|DELETE /api/ddos-protection/tcp-flow/{rules|filters}`
- `GET|PATCH|DELETE /api/ddos-protection/tcp-flow/{rules|filters}/:itemId`

## Account ID behavior

The Worker resolves account ID in this order:

1. `X-Account-ID` request header (UI uses this when override field is set)
2. `?accountId=` query param
3. `ACCOUNT_ID` Worker variable

This makes it easy to set a default account while allowing overrides for specific queries.
