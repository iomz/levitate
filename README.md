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

Levitate runs near local tools, launches one configured stdio MCP server, connects as an MCP client, then exposes a Streamable HTTP endpoint for Claude, ChatGPT, and other remote MCP hosts.

The project is **Levitate**. The package, CLI, Docker image, and binary artifact are `levitate`.

Initial target flow:

```text
Claude.ai / ChatGPT
  -> public HTTPS remote MCP endpoint
  -> Levitate
  -> local stdio MCP server
  -> private tool or data system
```

Levitate is backend-agnostic.
Any stdio MCP server can be exposed through its HTTP endpoint, subject to auth and policy.

## Why Promotion Exists

Many useful MCP servers are local stdio servers.
They work with Claude Desktop, Claude Code, Cursor, and other local MCP hosts, but cloud-hosted AI apps cannot connect to them directly.
Levitate promotes those local capabilities into a remote MCP endpoint while keeping policy and auth at the gateway.

## Security

Do not expose private local tools without authentication.

Levitate requires authentication for the MCP endpoint.
Static bearer tokens are available for local/dev/simple deployments.
OIDC/JWT validation is available for Auth0 and other RS256 JWKS-backed issuers.
MCP servers can read or modify private data, and tunnel-published endpoints are public unless protected.
`GET /health` reports process liveness and `GET /ready` reports stdio backend readiness.
Both endpoints are unauthenticated for deployment checks; the MCP endpoint requires `Authorization: Bearer <token>`.

## Quick Start

Install dependencies:

```sh
pnpm install
```

Set a bearer token:

```sh
export LEVITATE_TOKEN="$(openssl rand -hex 32)"
```

Start `levitate` with the fake stdio backend profile:

```sh
pnpm build
pnpm start -- --config config/fake-stdio.toml
```

MCP endpoint:

```text
http://127.0.0.1:8790/mcp
```

Health check:

```sh
curl http://127.0.0.1:8787/health
```

Readiness check:

```sh
curl http://127.0.0.1:8787/ready
```

Authenticated MCP clients must send:

```text
Authorization: Bearer <LEVITATE_TOKEN>
```

## Example Backend Profile

`config/fake-stdio.toml` shows one deterministic local profile for the fake stdio test backend:

```toml
[server]
name = "fake"
host = "127.0.0.1"
port = 8790
mcp_path = "/mcp"

[stdio]
command = "node"
args = ["test/fixtures/fake-stdio-server.mjs"]

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"
```

Real deployments can point `[stdio]` at any stdio MCP server and then use tool policy to filter or block exposed tools.

## Server Configuration

The MCP endpoint defaults to `/mcp`.
Set `server.mcp_path` to expose the single configured backend at another path:

```toml
[server]
name = "example"
mcp_path = "/brain/mcp"
```

The path must start with `/`.
`GET /health` remains unchanged.
This config does not enable multi-backend routing or backend aggregation.

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

## Auth Configuration

### Static bearer tokens

Static bearer mode reads a token from config or an environment variable:

```toml
[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"
```

Authenticated clients must send:

```text
Authorization: Bearer <LEVITATE_TOKEN>
```

### OIDC/JWT validation

OIDC mode validates incoming bearer JWTs against the configured issuer, audience, expiration, and JWKS signature:

```toml
[auth]
mode = "oidc"
issuer = "https://YOUR_TENANT.auth0.com/"
audience = "https://levitate.example.com"
jwks_uri = "https://YOUR_TENANT.auth0.com/.well-known/jwks.json"
```

`jwks_uri` is optional when the issuer's standard `/.well-known/jwks.json` path is correct.

Auth0 setup:

- Create an Auth0 Machine to Machine application for clients that need tokens.
- Create an Auth0 API with identifier `https://levitate.example.com`.
- Use RS256 signing.
- Configure Levitate with issuer `https://YOUR_TENANT.auth0.com/` and audience `https://levitate.example.com`.

Levitate only needs issuer, audience, and optionally JWKS URI to validate incoming tokens.
Auth0 client credentials are for clients or smoke scripts that obtain tokens; do not store client secrets in Levitate config.

Manual token acquisition for local smoke tests can use environment variables:

```sh
export AUTH0_DOMAIN=YOUR_TENANT.auth0.com
export AUTH0_AUDIENCE=https://levitate.example.com
export AUTH0_CLIENT_ID=...
export AUTH0_CLIENT_SECRET=...
```

Then request a token from:

```text
https://${AUTH0_DOMAIN}/oauth/token
```

### OAuth protected resource metadata

Levitate can serve OAuth protected resource metadata for remote MCP hosts that discover authorization details from the resource server:

```toml
[oauth.resource]
enabled = true
resource = "https://levitate.example.com/brain/mcp"
authorization_servers = ["https://auth.example.com/"]
scopes_supported = ["levitate:read", "levitate:call"]
```

When enabled, Levitate serves:

```text
GET /.well-known/oauth-protected-resource
```

The response includes the configured resource URL, authorization server list, `bearer_methods_supported = ["header"]`, and configured scopes.
`resource` is the canonical public MCP endpoint URL and must be configured explicitly.
Levitate does not derive it from issuer, audience, request host, or local bind address.

Unauthenticated or invalid-auth MCP requests keep the generic JSON body:

```json
{ "error": "auth failed" }
```

When protected resource metadata is enabled, the same `401` response includes:

```http
WWW-Authenticate: Bearer resource_metadata="https://levitate.example.com/.well-known/oauth-protected-resource"
```

By default, Levitate derives that metadata URL from the configured resource origin.
Set `oauth.resource.metadata_url` only when the public metadata URL needs an explicit override.

### Local OAuth authorization server facade

Levitate can run a private local OAuth authorization server facade for ChatGPT Custom MCP registration.
This exposes discovery, Dynamic Client Registration, authorization-code with PKCE, token issuance, and JWKS endpoints through the same HTTP server.
Use this only for private deployments that still require authenticated MCP requests.
Do not expose private local tools without auth and strict redirect URI configuration.

Example:

```toml
[server]
mcp_path = "/brain/mcp"

[oauth.resource]
enabled = true
resource = "https://levitate.example.com/brain/mcp"
authorization_servers = ["https://levitate.example.com"]
scopes_supported = ["brain:read", "brain:write"]

[oauth.as]
enabled = true
issuer = "https://levitate.example.com"
subject = "local-user"
approval = "auto"
approval_secret_env = "LEVITATE_APPROVAL_SECRET"
allowed_redirect_uri_prefixes = ["https://chatgpt.com/connector/oauth/"]
scopes_supported = ["brain:read", "brain:write"]
default_scopes = ["brain:read"]
access_token_ttl_seconds = 3600
authorization_code_ttl_seconds = 300
client_store_file = "state/oauth-clients.json"

[oauth.as.keys]
private_key_file = "state/oauth-private-key.pem"
key_id = "levitate-local-1"

[oauth.as.dcr]
enabled = true

[oauth.as.rate_limits]
window_seconds = 60
registration = 10
authorization = 30
token = 60
approval = 10

[auth]
mode = "levitate"
```

`oauth.as.keys.private_key_file` must point to an existing RSA private key.
Levitate fails startup when the local authorization server is enabled and the key is missing, unreadable, invalid, or not usable for RS256.
Levitate does not generate signing keys at runtime.

The local facade serves:

```text
GET  /.well-known/oauth-authorization-server
POST /oauth/register
GET  /oauth/authorize
POST /oauth/token
GET  /.well-known/jwks.json
```

ChatGPT Custom MCP flow:

```text
ChatGPT
  -> reads /.well-known/oauth-protected-resource
  -> reads /.well-known/oauth-authorization-server
  -> registers a public client at /oauth/register
  -> completes authorization_code + PKCE through /oauth/authorize and /oauth/token
  -> receives a Levitate-issued RS256 JWT access token
  -> calls the configured MCP endpoint with Authorization: Bearer <token>
```

Dynamic Client Registration accepts public clients only.
Registered redirect URIs must be absolute HTTPS URLs and match `oauth.as.allowed_redirect_uri_prefixes`.
Levitate does not issue client secrets.
Authorization codes are short-lived, single-use, and stored in memory only.
Pending approvals and authorization codes are pruned periodically and discarded on process exit.
Cleanup timers do not keep Levitate running during shutdown.
Registered clients persist in the JSON file configured by `oauth.as.client_store_file`.

### Credential lifecycle and storage limits

Current JSON client store uses atomic file replacement and serializes writes made through one Levitate process.
It does not coordinate read-modify-write operations across processes or nodes.
Run one Levitate server against each client store and stop that server before using mutating client-management commands.
Future multi-node storage can implement the internal client-store interface without changing OAuth route logic.

Client revocation blocks new authorization requests and token exchanges, including exchanges using authorization codes issued before revocation.
Already-issued access tokens remain valid until their configured expiration because Levitate does not maintain an access-token denylist.
Use short access-token lifetimes where rapid revocation matters.

Current signing configuration supports one active RSA key and publishes one JWK.
Changing the private key or key ID invalidates every token signed by the previous key immediately.
Safe current rotation procedure is: stop Levitate, replace the key file, change `oauth.as.keys.key_id`, restart Levitate, then reauthorize clients.
Overlapping old/new verification keys and zero-interruption rotation are not implemented.

DCR is closed by default.
Temporarily set `[oauth.as.dcr] enabled = true` while installing a ChatGPT Custom App, then set it back to `false` after the client appears in `oauth.as.client_store_file`.
Existing registered clients can still authorize and exchange tokens while DCR is disabled.

OAuth rate limits are optional and process-local.
When configured, registration uses one gateway-wide bucket while authorization, token, and approval requests use client-specific buckets where a validated client identifier is available.
Exceeded limits return `429` with `Retry-After` and do not log submitted secrets, codes, tokens, or PKCE verifiers.
Multi-node deployments require a shared limiter design before these limits can provide deployment-wide enforcement.
OAuth security logs include stable `event`, `outcome`, and `requestId` fields for registration, authorization, approval, and token exchange.
Audit logs never include submitted client metadata bodies, approval secrets, authorization codes, access tokens, or PKCE verifiers.

`approval = "auto"` immediately issues authorization codes after validation and is intended for private tests or temporary setup.
Set `approval = "manual"` to require an explicit owner approval page before Levitate issues an authorization code.
Manual approval requires `oauth.as.approval_secret_env`, and the referenced environment variable must contain the approval secret.
Manual approval displays the client, redirect origin, requested resource, scopes, and registration type after client, redirect URI, resource, scope, and PKCE validation pass, then requires the approval secret before approving.
Canceling an approval request does not require the approval secret because it only returns `access_denied`.
Approval and denial responses do not expose tokens, authorization codes, local filesystem paths, or stack traces.

Example:

```sh
export LEVITATE_APPROVAL_SECRET="$(openssl rand -base64 32)"
```

Manage registered clients from the same config:

```sh
levitate oauth clients list --config config/example.local.toml
levitate oauth clients show <client_id> --config config/example.local.toml
levitate oauth clients revoke <client_id> --config config/example.local.toml
```

Revoked clients cannot start new authorization flows or exchange already-issued authorization codes.
Already-issued access tokens remain valid until expiration.

Access tokens are RS256 JWTs with `iss`, `sub`, `aud`, `scope`, `exp`, `iat`, and `client_id`.
`auth.mode = "levitate"` validates only Levitate-issued JWTs against the configured issuer, resource audience, public key, expiration, algorithm, and client ID claim.
Existing `auth.mode = "oidc"` remains available separately for Auth0 and other external RS256 JWKS-backed issuers.

Auth0-backed Dynamic Client Registration, CIMD, refresh tokens, hosted login UI, and multi-user management are not implemented.

## Tool Policy

Levitate filters backend tools before advertising them to remote clients.

Rules:

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

Levitate passes these instructions through the MCP server initialization result using the official TypeScript SDK `Server` `instructions` option.

## Multi-backend Routing Model

Levitate is intended to host multiple MCP backends by assigning each backend its own HTTP MCP endpoint:

- `/notes/mcp`
- `/ingest/mcp`
- `/tools/mcp`
- `/example/mcp`

Each endpoint should behave as an independent MCP server backed by one stdio MCP backend.

Levitate does not merge multiple backend tool namespaces into a single `/mcp` endpoint by default.
MCP already provides tool discovery through `tools/list`, so Levitate should preserve backend tool names and schemas unless an explicit policy filters or blocks them.

This keeps Levitate transport-transparent and avoids tool-name collisions, namespace rewriting, ambiguous routing, and policy mistakes.
If an aggregate MCP endpoint is ever needed, it should be treated as a separate explicit feature, not the default multi-backend model.

## Tunnel Deployment

Run `levitate` locally, then expose it with Cloudflare Tunnel, ngrok, or another HTTPS tunnel:

```sh
cloudflared tunnel --url http://127.0.0.1:8787
```

or:

```sh
ngrok http 8787
```

Configure the AI app connector to use the public HTTPS MCP URL and bearer token.

## Smoke Tests

### Fake stdio backend

Use the fake stdio backend for deterministic local checks of Levitate's HTTP proxy and policy behavior:

```sh
export LEVITATE_TOKEN="dev-secret"
pnpm build
pnpm start -- --config config/fake-stdio.toml
```

In another terminal, connect MCP Inspector over Streamable HTTP with bearer auth:

```sh
npx -y @modelcontextprotocol/inspector@0.22.0 \
  --cli \
  --transport http \
  --header "Authorization: Bearer ${LEVITATE_TOKEN}" \
  -- http://127.0.0.1:8790/mcp \
  --method tools/list
```

Call the allowed tool:

```sh
npx -y @modelcontextprotocol/inspector@0.22.0 \
  --cli \
  --transport http \
  --header "Authorization: Bearer ${LEVITATE_TOKEN}" \
  -- http://127.0.0.1:8790/mcp \
  --method tools/call \
  --tool-name fake_allowed \
  --tool-arg message=hello
```

Call the denied tool directly:

```sh
npx -y @modelcontextprotocol/inspector@0.22.0 \
  --cli \
  --transport http \
  --header "Authorization: Bearer ${LEVITATE_TOKEN}" \
  -- http://127.0.0.1:8790/mcp \
  --method tools/call \
  --tool-name fake_denied
```

Expected result:

- initialize succeeds
- `tools/list` advertises `fake_allowed`
- `fake_denied` is not advertised
- calling `fake_allowed` returns fixture JSON
- directly calling `fake_denied` returns an MCP tool error from Levitate

The automated version is covered by:

```sh
pnpm test test/mcp.test.ts
```

### Optional local real-backend smoke test

You can test Levitate against any real stdio MCP backend using a local config.
This is not required for normal development or CI.
Create a local config that points to your backend, then choose one safe allowed tool and one denied tool for policy testing.

```sh
export LEVITATE_TOKEN="$(openssl rand -hex 32)"
export LEVITATE_CONFIG="config/example.local.toml"
export LEVITATE_SAFE_TOOL="example_safe_tool"
export LEVITATE_DENIED_TOOL="example_denied_tool"
pnpm build
pnpm start -- --config "$LEVITATE_CONFIG"
```

In another terminal, connect MCP Inspector:

```sh
npx -y @modelcontextprotocol/inspector@0.22.0 \
  --cli \
  --transport http \
  --header "Authorization: Bearer ${LEVITATE_TOKEN}" \
  -- http://127.0.0.1:8787/mcp \
  --method tools/list
```

Call a safe read-only tool:

```sh
npx -y @modelcontextprotocol/inspector@0.22.0 \
  --cli \
  --transport http \
  --header "Authorization: Bearer ${LEVITATE_TOKEN}" \
  -- http://127.0.0.1:8787/mcp \
  --method tools/call \
  --tool-name "$LEVITATE_SAFE_TOOL"
```

Call a denied tool directly:

```sh
npx -y @modelcontextprotocol/inspector@0.22.0 \
  --cli \
  --transport http \
  --header "Authorization: Bearer ${LEVITATE_TOKEN}" \
  -- http://127.0.0.1:8787/mcp \
  --method tools/call \
  --tool-name "$LEVITATE_DENIED_TOOL"
```

If a tool requires arguments, add `--tool-arg key=value` entries according to the backend's advertised input schema.

Verify in Inspector:

- initialize succeeds
- `tools/list` shows allowed backend tools
- allowed tool calls work through Levitate
- denied direct calls return an MCP tool error instead of an HTTP error or server crash

MCP Inspector `0.22.0` CLI supports HTTP headers with `--header`, so the smoke test keeps bearer-token auth enabled.
The browser UI path may require entering headers in the UI; use the CLI commands above as the reproducible smoke path.

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

For local stdio servers that need host files, mount required vault/tool paths and adjust config paths for the container.

## Auth Notes

OIDC/JWT validation and Levitate-issued JWT validation run behind the same `Authenticator` interface as static bearer tokens.

OIDC validation checks:

- JWKS signature
- issuer
- audience
- expiration
- not-before when present
- subject or email allowlists when configured

Levitate-issued JWT validation checks:

- JWKS signature from the configured local authorization server key
- issuer
- resource audience
- expiration
- RS256 algorithm
- `client_id` claim
- scopes

Only RS256 JWTs are accepted for OIDC and local authorization server modes.
Static bearer auth remains available for local/dev/simple deployments.

## MCP Transport Choice

Levitate uses the official `@modelcontextprotocol/sdk` v1 Streamable HTTP implementation:

- backend: `StdioClientTransport`
- remote endpoint: `WebStandardStreamableHTTPServerTransport`
- HTTP framework: Hono, following the SDK Hono example

The remote endpoint defaults to `/mcp` and uses JSON responses from Streamable HTTP for straightforward request/response behavior.
Deployments can change the endpoint path with `server.mcp_path`.
Compatibility should be validated against each target remote MCP host because Claude, ChatGPT, and other hosts may differ in connector rollout details.

## Non-Goals

- No web UI
- No Chrome extension
- No WebRTC mode
- No OAuth login UI
- No hosted multi-user approval UI
- No multi-user management
- No multi-profile routing
- No persistent audit database
- No backend-specific wrapper behavior
- No Go or Rust rewrite plan

## Validation

```sh
pnpm test
pnpm typecheck
pnpm build
```
