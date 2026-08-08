# Authentication

Levitate requires authentication for every MCP endpoint.
Choose one mode for the gateway:

| Mode | Use case | Configuration |
| --- | --- | --- |
| Static bearer | Local, private, or manually managed deployments | `auth.mode = "bearer"` |
| External OIDC | Auth0 or another RS256 JWKS-backed issuer | `auth.mode = "oidc"` |
| Levitate OAuth | Private ChatGPT-compatible deployments using Levitate-issued tokens | `auth.mode = "levitate"` |

The health and readiness endpoints remain unauthenticated for deployment checks.
CORS limits browser origins but does not replace authentication.

## Static bearer tokens

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

See [`config/bearer.example.toml`](config/bearer.example.toml).

## External OIDC/JWT validation

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
Auth0 client credentials belong to clients or smoke scripts that obtain tokens; do not store client secrets in Levitate config.

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

See [`config/oidc.example.toml`](config/oidc.example.toml).

## OAuth protected resource metadata

Levitate can serve OAuth protected resource metadata for remote MCP hosts that discover authorization details from the resource server:

```toml
[oauth.resource]
enabled = true
mode = "service"
resource = "https://levitate.example.com/brain/mcp"
authorization_servers = ["https://auth.example.com/"]
scopes_supported = ["levitate:read", "levitate:call"]
```

When enabled, Levitate serves:

```text
GET /.well-known/oauth-protected-resource
GET /.well-known/oauth-protected-resource/brain/mcp
```

The path-scoped route follows the configured public resource path; the root route remains available for compatibility.
Both responses include the configured resource URL, authorization server list, `bearer_methods_supported = ["header"]`, and configured scopes.
`resource` is the canonical public MCP endpoint URL and must be configured explicitly.
Levitate does not derive it from issuer, audience, request host, or local bind address.

Unauthenticated or invalid-auth MCP requests keep the generic JSON body:

```json
{ "error": "auth failed" }
```

When protected resource metadata is enabled, the same `401` response includes:

```http
WWW-Authenticate: Bearer resource_metadata="https://levitate.example.com/.well-known/oauth-protected-resource/brain/mcp"
```

By default, Levitate derives the path-scoped metadata URL from the configured resource URL.
Set `oauth.resource.metadata_url` only when the public metadata URL needs an explicit override.
`mode = "service"` is the default and binds the resource identity to one canonical MCP endpoint.
Gateway mode derives one metadata URL per backend and therefore rejects this single-URL override.

## Local OAuth authorization server

Levitate can run a private OAuth authorization server for ChatGPT and other remote MCP hosts.
It exposes discovery, Client ID Metadata Document (CIMD) resolution, optional Dynamic Client Registration (DCR), authorization code with PKCE, token issuance, and JWKS endpoints through the same HTTP server.
Use it only for private deployments that still require authenticated MCP requests.
Do not expose private local tools without authentication and strict redirect URI configuration.

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
approval = "manual"
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
enabled = false

[oauth.as.cimd]
enabled = true
allowed_client_id_prefixes = ["https://chatgpt.com/"]

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
Levitate fails startup when the local authorization server is enabled and the key is missing, unreadable, invalid, or unusable for RS256.
Levitate does not generate signing keys at runtime.

The local server exposes:

```text
GET  /.well-known/oauth-authorization-server
POST /oauth/register
GET  /oauth/authorize
POST /oauth/token
GET  /.well-known/jwks.json
```

ChatGPT flow:

```text
ChatGPT
  -> reads /.well-known/oauth-protected-resource/brain/mcp
  -> reads /.well-known/oauth-authorization-server
  -> supplies an HTTPS client_id that points to its metadata document
  -> Levitate fetches and validates that allowlisted document
  -> completes authorization_code + PKCE through /oauth/authorize and /oauth/token
  -> receives a Levitate-issued RS256 JWT access token
  -> calls the configured MCP endpoint with Authorization: Bearer <token>
```

See [`config/oauth-as.example.toml`](config/oauth-as.example.toml).
ChatGPT installation steps remain in [README](README.md#install-a-levitate-endpoint-in-chatgpt).

### CIMD and DCR

CIMD is preferred and advertised through authorization-server metadata when enabled.
Only HTTPS client IDs matching `oauth.as.cimd.allowed_client_id_prefixes` are fetched.
Redirects are rejected; response size, time, fetch rate, and cache cardinality are bounded; documents must identify themselves exactly.
CIMD redirect URIs must also match `oauth.as.allowed_redirect_uri_prefixes`.
CIMD clients remain external rather than being persisted in Levitate's client store.

DCR remains an optional fallback and accepts public clients only.
Registered redirect URIs must be absolute HTTPS URLs and match `oauth.as.allowed_redirect_uri_prefixes`.
Levitate does not issue client secrets.
Authorization codes are short-lived, single-use, and stored in memory only.
Pending approvals and authorization codes are pruned periodically and discarded on process exit.
Cleanup timers do not keep Levitate running during shutdown.
Registered clients persist in the JSON file configured by `oauth.as.client_store_file`.

DCR is closed by default and unnecessary when the client supports CIMD.
For clients without CIMD support, temporarily set `[oauth.as.dcr] enabled = true` while installing, then set it back to `false` after client appears in `oauth.as.client_store_file`.
Existing registered clients can still authorize and exchange tokens while DCR is disabled.

## Gateway-wide OAuth identity

Multiple named backends can share one explicit local OAuth identity when every authenticated connector should access every backend in the gateway.
Set `oauth.resource.mode = "gateway"` and use the public origin, without a path, as the canonical resource:

```toml
[oauth.resource]
enabled = true
mode = "gateway"
resource = "https://levitate.example.com"
authorization_servers = ["https://levitate.example.com"]
scopes_supported = ["gateway:access"]

[auth]
mode = "levitate"

[backends.notes]
mcp_path = "/notes/mcp"
[backends.notes.stdio]
command = "notes-mcp"

[backends.ingest]
mcp_path = "/ingest/mcp"
[backends.ingest.stdio]
command = "ingest-mcp"
```

Levitate serves path-scoped protected-resource metadata for every backend:

```text
/.well-known/oauth-protected-resource/notes/mcp
/.well-known/oauth-protected-resource/ingest/mcp
```

Every metadata document returns the same origin-level resource.
ChatGPT echoes that exact resource through authorization and token exchange, and Levitate issues one token whose audience is the gateway origin.
That token works on every named MCP path while each backend keeps its own process, instructions, readiness state, and tool policy.
Configured `mcp_path` values must match the public HTTPS paths exposed by the reverse proxy in gateway mode.

Gateway mode intentionally creates one authorization boundary.
A leaked or misbehaving connector token can reach every backend, subject to backend tool policies.
Use service mode or separate Levitate deployments when backends need separate token audiences.

See [`config/oauth-gateway.example.toml`](config/oauth-gateway.example.toml) for runnable ChatGPT-oriented configuration.

## Approval and client management

`approval = "auto"` immediately issues authorization codes after validation and is intended for private tests or temporary setup.
Set `approval = "manual"` to require an explicit owner approval page before Levitate issues an authorization code.
Manual approval requires `oauth.as.approval_secret_env`, and the referenced environment variable must contain the approval secret.
Manual approval displays the client, redirect origin, requested resource, scopes, and registration type after validation, then requires the approval secret before approving.
Canceling an approval request does not require the approval secret because it only returns `access_denied`.
Approval and denial responses do not expose tokens, authorization codes, local filesystem paths, or stack traces.

Generate an approval secret:

```sh
export LEVITATE_APPROVAL_SECRET="$(openssl rand -base64 32)"
```

Manage registered clients from the same config:

```sh
levitate oauth clients list --config config/example.local.toml
levitate oauth clients show <client_id> --config config/example.local.toml
levitate oauth clients revoke <client_id> --config config/example.local.toml
```

Client revocation blocks new authorization requests and token exchanges, including exchanges using authorization codes issued before revocation.
Already-issued access tokens remain valid until expiration because Levitate does not maintain an access-token denylist.
Use short access-token lifetimes where rapid revocation matters.

## Storage, rotation, and rate limits

Current JSON client store uses atomic file replacement and serializes writes made through one Levitate process.
It does not coordinate read-modify-write operations across processes or nodes.
Run one Levitate server against each client store and stop that server before using mutating client-management commands.
Future multi-node storage can implement internal client-store interface without changing OAuth route logic.

Current signing configuration supports one active RSA key and publishes one JWK.
Changing the private key or key ID invalidates every token signed by the previous key immediately.
Safe current rotation procedure: stop Levitate, replace the key file, change `oauth.as.keys.key_id`, restart Levitate, then reauthorize clients.
Overlapping old/new verification keys and zero-interruption rotation are not implemented.

OAuth rate limits are optional and process-local.
When configured, registration uses one gateway-wide bucket while authorization, token, and approval requests use client-specific buckets keyed by submitted client identifier.
Exceeded limits return `429` with `Retry-After` and do not log submitted secrets, codes, tokens, or PKCE verifiers.
Multi-node deployments require a shared limiter design before these limits can provide deployment-wide enforcement.

OAuth security logs include stable `event`, `outcome`, and `requestId` fields for registration, authorization, approval, and token exchange.
Audit logs never include submitted client metadata bodies, approval secrets, authorization codes, access tokens, or PKCE verifiers.

## Validation behavior

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
Access tokens contain `iss`, `sub`, `aud`, `scope`, `exp`, `iat`, and `client_id`.
`auth.mode = "levitate"` validates only Levitate-issued JWTs against the configured issuer, resource audience, public key, expiration, algorithm, and client ID claim.
`auth.mode = "oidc"` remains available separately for Auth0 and other external RS256 JWKS-backed issuers.
Static bearer authentication remains available for local, development, and simple deployments.

Auth0-backed DCR, refresh tokens, `private_key_jwt`, hosted login UI, and multi-user management are not implemented.
