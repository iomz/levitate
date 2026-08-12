<p align="center">
  <img width="160" height="160" alt="Levitate app icon" src="assets/levitate-icon.png" />
</p>

<h1 align="center">Levitate</h1>

<p align="center">
  Local-first gateway for exposing stdio MCP servers as remote MCP endpoints.
</p>

<p align="center">
  <a href="https://github.com/iomz/levitate/actions/workflows/ci.yml"><img src="https://github.com/iomz/levitate/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License"></a>
</p>

Levitate runs near local tools, launches one or more configured stdio MCP servers, connects as an MCP client, then exposes Streamable HTTP endpoints for Claude, ChatGPT, and other remote MCP hosts.

```text
Claude.ai / ChatGPT
  -> public HTTPS remote MCP endpoint
  -> Levitate
  -> local stdio MCP server
  -> private tool or data system
```

Levitate is backend-agnostic.
Any stdio MCP server can be exposed through its own HTTP endpoint, subject to gateway authentication and backend-specific policy.
Package, CLI, Docker image, and binary artifact are named `levitate`.

## Why Levitate

Many useful MCP servers expose only local stdio transport.
They work with Claude Desktop, Claude Code, Cursor, and other local MCP hosts, but cloud-hosted AI apps cannot connect directly.
Levitate promotes those capabilities into remote MCP endpoints while keeping authentication and policy at the gateway.

## Documentation

- [Authentication](AUTHENTICATION.md): bearer, OIDC, protected-resource metadata, local OAuth, CIMD/DCR, gateway identity, and credential operations
- [Testing](TESTING.md): automated validation and MCP Inspector smoke tests
- [`config/`](config): copyable deployment examples

## Security

Do not expose private local tools without authentication.

Levitate requires authentication for MCP endpoints.
Static bearer tokens support local and simple deployments.
OIDC/JWT validation supports Auth0 and other RS256 JWKS-backed issuers.
Levitate can also issue gateway tokens through its local OAuth server for private ChatGPT-compatible deployments.

MCP servers can read or modify private data, and tunnel-published endpoints are public unless protected.
`GET /health` reports process liveness and `GET /ready` reports backend readiness.
Both endpoints are unauthenticated for deployment checks; MCP endpoints require bearer authentication.
Shutdown stops accepting HTTP traffic, gives existing connections one second to close, then force-closes all remaining HTTP connections before exiting.
In-flight requests may terminate after this grace period.

See [Authentication](AUTHENTICATION.md) before publishing Levitate through a tunnel or reverse proxy.

## Quick Start

Install dependencies:

```sh
pnpm install
```

Set a bearer token and start the deterministic fake backend:

```sh
export LEVITATE_TOKEN="$(openssl rand -hex 32)"
pnpm build
pnpm start -- --config config/fake-stdio.toml
```

The fake profile listens on port `8790`:

```text
http://127.0.0.1:8790/mcp
```

Check process and backend:

```sh
curl http://127.0.0.1:8790/health
curl http://127.0.0.1:8790/ready
```

Authenticated MCP clients must send:

```text
Authorization: Bearer <LEVITATE_TOKEN>
```

See [Testing](TESTING.md) for MCP Inspector commands and expected results.

## Configuration

Choose the smallest example matching the deployment:

| Use case | Example | Notes |
| --- | --- | --- |
| Static bearer token | [`config/bearer.example.toml`](config/bearer.example.toml) | Small local, private, or manually managed deployment |
| External OIDC/JWT | [`config/oidc.example.toml`](config/oidc.example.toml) | Auth0 or another RS256 JWKS-backed provider |
| Local OAuth server | [`config/oauth-as.example.toml`](config/oauth-as.example.toml) | ChatGPT with CIMD/DCR, PKCE, manual approval, and local JWT issuance |
| Gateway-wide OAuth | [`config/oauth-gateway.example.toml`](config/oauth-gateway.example.toml) | One OAuth identity shared by multiple named backends |
| Multiple backends | [`config/multi-backend.example.toml`](config/multi-backend.example.toml) | Independent routes, processes, instructions, and tool policies behind shared authentication |

Copy an example to an ignored local file before adding machine paths or deployment values:

```sh
cp config/bearer.example.toml config/bearer.local.toml
```

Example files contain no secrets.
Prefer environment variables for bearer tokens and approval secrets.
Use absolute state and key paths when Levitate runs under a service manager with a different working directory.

### Server endpoint

The MCP endpoint defaults to `/mcp`.
Set `server.mcp_path` to expose a single backend at another path:

```toml
[server]
name = "example"
mcp_path = "/brain/mcp"
```

The path must start with `/`.
`GET /health` remains unchanged.
This setting alone does not enable multi-backend routing or backend aggregation.

### CORS

Levitate permits every browser origin by default for backward compatibility.
Restrict browser access with an exact origin allowlist:

```toml
[server.cors]
allowed_origins = ["https://chatgpt.com", "https://example.com"]
```

Origins must use HTTP or HTTPS and cannot contain paths, queries, or fragments.
Requests without an `Origin` header remain available to non-browser MCP clients.
CORS does not replace bearer authentication or OAuth validation.

### Authentication

Authentication applies at the gateway level.
Supported modes:

- static bearer token
- external OIDC/JWT validation
- Levitate-issued OAuth tokens

Named backends can use one gateway-wide OAuth audience when every authenticated connector should access every backend.
Use service mode or separate Levitate deployments when backends need separate token audiences.

See [Authentication](AUTHENTICATION.md) for configuration, discovery endpoints, CIMD/DCR behavior, approval, client management, key rotation, and storage limits.

## Tool Policy

Levitate filters backend tools before advertising them to remote clients.

- If `tools.allow` is configured, only listed tools are advertised and callable.
- `tools.deny` is always enforced as an extra guard.
- Direct calls to denied tools return an MCP tool error and are logged.

This lets a private backend expose read-only or append-only tools while hiding destructive tools.

## Server Instructions

Instructions can be configured inline or loaded from a file:

```toml
[instructions]
file = "/path/to/SKILL.md"
```

Levitate passes instructions through MCP server initialization using official TypeScript SDK `Server` `instructions` option.

## Multi-backend Routing

Levitate can host multiple MCP backends by assigning each backend its own HTTP MCP endpoint:

```text
/notes/mcp
/ingest/mcp
/tools/mcp
```

Each endpoint behaves as an independent MCP server backed by one stdio process.

```toml
[server]
name = "private-gateway"
host = "127.0.0.1"
port = 8787

[backends.notes]
mcp_path = "/notes/mcp"
[backends.notes.stdio]
command = "notes-mcp"
[backends.notes.tools]
deny = ["delete_note"]

[backends.ingest]
mcp_path = "/ingest/mcp"
[backends.ingest.stdio]
command = "ingest-mcp"
```

Named backends cannot be combined with the legacy top-level `[stdio]` configuration.
Backend paths must be unique and cannot overlap health, readiness, OAuth, or well-known routes.
Policies, instructions, environment, process lifecycle, and readiness remain backend-specific.
`GET /ready` succeeds only when every backend is ready and includes per-backend states.
Startup failure closes every backend already started before Levitate exits.

Static bearer and external OIDC authentication apply at gateway level across every backend.
Local Levitate OAuth can also apply at gateway level when `oauth.resource.mode = "gateway"` uses one origin-level audience for every backend.
Service mode remains rejected with multiple named backends so a token naming one MCP path is never silently accepted by another.

Levitate does not merge backend tool namespaces into one `/mcp` endpoint.
MCP already provides tool discovery through `tools/list`, so Levitate preserves backend tool names and schemas unless explicit policy filters or blocks them.
This avoids tool-name collisions, namespace rewriting, ambiguous routing, and policy mistakes.

## Install a Levitate Endpoint in ChatGPT

ChatGPT UI labels can change independently of Levitate.
These steps were verified in ChatGPT developer mode on 2026-08-09; also check OpenAI's current [connection guide](https://developers.openai.com/plugins/deploy/connect-chatgpt).

Before installing an endpoint, enable ChatGPT developer mode under **Settings > Security and login** and confirm Levitate is reachable through public HTTPS.
Some ChatGPT builds also expose Developer mode under **Settings > Plugins**.
Create one ChatGPT plugin entry for each named MCP endpoint that should appear separately.

1. Open the plugin browser from **Plugins** in the ChatGPT sidebar, or use **Settings > Plugins > Browse plugins**.
2. Select **+** in the top-right corner.
3. Complete the **New Plugin** dialog:

   | Field | Value |
   | --- | --- |
   | Icon | Optional. [`assets/levitate-icon-64.png`](assets/levitate-icon-64.png) fits current 10 KB upload limit. |
   | Name | Any clear per-endpoint name, such as `Levitate/Notes` or `Levitate/Admin`. |
   | Description | Optional. |
   | Connection | Select **Server URL** and enter full MCP endpoint, such as `https://levitate.example.com/notes/mcp`. |
   | Authentication | Select **OAuth**. Levitate requires OAuth discovery; Streamable HTTP is not an authentication option. |

4. Review the custom MCP server warning, then check **I understand and want to continue**.
5. Select **Create**.
6. In **Add <plugin name> to ChatGPT**, select **Sign in with <plugin name>**.
7. On the Levitate approval page, verify the client, redirect origin, resource, scopes, and registration method.
8. Enter the approval secret stored in the environment variable named by `oauth.as.approval_secret_env`, then select **Approve**.
9. Enable the new plugin in a ChatGPT conversation and invoke one of its tools.

The approval secret is not an access token.
Levitate issues the access token only after approval and ChatGPT's authorization-code and PKCE exchange.
Clients registered for the `refresh_token` grant receive a rotating refresh token, allowing ChatGPT to renew expired access tokens without repeating manual approval.
Each rotation renews the refresh token for `oauth.as.refresh_token_ttl_seconds`; inactive connections eventually expire, while active connections remain linked.
Reuse of a rotated token revokes its family.
Levitate stores only refresh-token hashes in the mode-`0600` file configured by `oauth.as.refresh_token_store_file`.
When that path is omitted, Levitate derives it from `oauth.as.client_store_file`.
Do not paste the approval secret into a ChatGPT conversation.

Selecting **OAuth** does not choose between CIMD and DCR.
The Levitate approval page reports which registration method ChatGPT used.
If it reports **Dynamic Client Registration**, the connection tested DCR rather than CIMD; an existing registered DCR client remains usable after new DCR registrations are disabled.
For a CIMD-only deployment, keep `oauth.as.dcr.enabled = false`, enable `oauth.as.cimd`, and treat the CIMD registration label on the approval page as smoke-test evidence.

## Public HTTPS Deployment

Run Levitate locally, then expose it through reverse proxy, Cloudflare Tunnel, ngrok, or another HTTPS tunnel:

```sh
cloudflared tunnel --url http://127.0.0.1:8787
```

or:

```sh
ngrok http 8787
```

Configure the remote MCP host with the public HTTPS endpoint and selected authentication mode.

## Docker

Build:

```sh
docker build -t levitate .
```

Run:

```sh
docker run --rm -p 8787:8787 \
  -e LEVITATE_TOKEN="$LEVITATE_TOKEN" \
  -v "$PWD/config:/app/config:ro" \
  levitate
```

For local stdio servers that need host files, mount the required vault or tool paths and adjust config paths for the container.

## MCP Transport

Levitate uses the official `@modelcontextprotocol/sdk` v1 Streamable HTTP implementation:

- backend: `StdioClientTransport`
- remote endpoint: `WebStandardStreamableHTTPServerTransport`
- HTTP framework: Hono, following the SDK Hono example

The remote endpoint defaults to `/mcp` and uses JSON responses from Streamable HTTP for straightforward request/response behavior.
Deployments can change the endpoint path with `server.mcp_path` or define independent paths for named backends.
During MCP initialization, Levitate advertises its package version, human-readable title, description, project website, and 64x64 PNG icon through `serverInfo`.
The icon is available without authentication at `/assets/levitate-icon-64.png`; clients decide whether and where to display the metadata.
Compatibility should be validated against each target remote MCP host because connector behavior can differ.

## Non-Goals

- Hosted multi-user service or multi-user management
- Automatic aggregation of backend tool namespaces
- Backend-specific wrapper behavior
- Shared multi-node OAuth state, rate limits, or zero-interruption key rotation
- Persistent audit database

## Development

See [Testing](TESTING.md) for full validation and smoke-test workflow.

```sh
pnpm test
pnpm typecheck
pnpm build
```
