# Levitate

Levitate lifts local stdio MCP servers into remote AI app connectors for Claude, ChatGPT, and other MCP hosts.

Levitate is a local-first gateway. It runs near local tools, launches one configured stdio MCP server, connects as an MCP client, then exposes a remote MCP Streamable HTTP endpoint for cloud-hosted AI clients.

Initial target flow:

```text
Claude.ai / ChatGPT
  -> public HTTPS remote MCP endpoint
  -> Levitate
  -> local stdio MCP server
  -> private tool or data system
```

Levitate is backend-agnostic. Any stdio MCP server can be exposed through a Streamable HTTP endpoint, subject to auth and policy.

## Why Promotion Exists

Many useful MCP servers are local stdio servers. They work with Claude Desktop, Claude Code, Cursor, and other local MCP hosts, but cloud-hosted AI apps cannot connect to them directly. Levitate promotes those local capabilities into a remote MCP endpoint while keeping policy and auth at the gateway.

## Security

Do not expose private local tools without authentication.

Levitate requires bearer-token auth for the MCP endpoint in the MVP. This is intentional: MCP servers can read or modify private data, and tunnel-published endpoints are public unless protected. `GET /health` is unauthenticated for deployment checks; `/mcp` requires `Authorization: Bearer <token>`.

## Quick Start

Install dependencies:

```sh
pnpm install
```

Set a bearer token:

```sh
export LEVITATE_TOKEN="$(openssl rand -hex 32)"
```

Start Levitate with the fake stdio backend profile:

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

[stdio]
command = "node"
args = ["test/fixtures/fake-stdio-server.mjs"]

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"
```

Real deployments can point `[stdio]` at any stdio MCP server and then use tool policy to filter or block exposed tools.

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

Levitate does not merge multiple backend tool namespaces into a single `/mcp` endpoint by default. MCP already provides tool discovery through `tools/list`, so Levitate should preserve backend tool names and schemas unless an explicit policy filters or blocks them.

This keeps Levitate transport-transparent and avoids tool-name collisions, namespace rewriting, ambiguous routing, and policy mistakes. If an aggregate MCP endpoint is ever needed, it should be treated as a separate explicit feature, not the default multi-backend model.

## Tunnel Deployment

Run Levitate locally, then expose it with Cloudflare Tunnel, ngrok, or another HTTPS tunnel:

```sh
cloudflared tunnel --url http://127.0.0.1:8787
```

or:

```sh
ngrok http 8787
```

Configure the AI app connector to use the public HTTPS `/mcp` URL and bearer token.

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

You can test Levitate against any real stdio MCP backend using a local config. This is not required for normal development or CI. Create a local config that points to your backend, then choose one safe allowed tool and one denied tool for policy testing.

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

MCP Inspector `0.22.0` CLI supports HTTP headers with `--header`, so the smoke test keeps bearer-token auth enabled. The browser UI path may require entering headers in the UI; use the CLI commands above as the reproducible smoke path.

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

## Auth Roadmap

MVP auth is static bearer token.

Next auth layer should add OIDC/JWKS validation behind the existing `Authenticator` interface. Auth0 is the recommended hosted IdP. Authentik is an important compatibility target via standard OIDC.

Future OIDC validation must check:

- JWKS signature
- issuer
- audience
- expiration
- not-before when present
- subject or email allowlists when configured

No fake OIDC is implemented in the MVP.

## MCP Transport Choice

Levitate uses the official `@modelcontextprotocol/sdk` v1 Streamable HTTP implementation:

- backend: `StdioClientTransport`
- remote endpoint: `WebStandardStreamableHTTPServerTransport`
- HTTP framework: Hono, following the SDK Hono example

The remote endpoint is `/mcp` and uses JSON responses from Streamable HTTP for straightforward request/response behavior. Compatibility should be validated against each target remote MCP host because Claude, ChatGPT, and other hosts may differ in connector rollout details.

## Non-Goals

- No web UI
- No Chrome extension
- No WebRTC mode
- No OAuth login UI
- No approval UI
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
