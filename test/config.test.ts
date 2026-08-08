import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { getBackendConfigs, parseConfigText } from "../src/config.js";

describe("config parsing", () => {
  it("rejects empty named backends combined with legacy stdio", () => {
    expect(() => parseConfigText(`
[server]
name = "gateway"
[stdio]
command = "node"
[backends]
[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"
`)).toThrow("stdio and backends cannot be configured together");
  });

  it("rejects reserved legacy MCP paths", () => {
    expect(() => parseConfigText(`
[server]
name = "gateway"
mcp_path = "/health"
[stdio]
command = "node"
[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"
`)).toThrow("backend mcp_path is reserved: /health");
  });
  it("normalizes named multi-backend configuration", () => {
    const config = parseConfigText(`
[server]
name = "gateway"

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"

[backends.notes]
mcp_path = "/notes/mcp"
[backends.notes.stdio]
command = "notes-mcp"
[backends.notes.tools]
deny = ["delete_note"]

[backends.ingest]
name = "health-ingest"
mcp_path = "/ingest/mcp"
[backends.ingest.stdio]
command = "ingest-mcp"
`);

    expect(getBackendConfigs(config)).toEqual([
      expect.objectContaining({ id: "notes", name: "notes", mcp_path: "/notes/mcp" }),
      expect.objectContaining({ id: "ingest", name: "health-ingest", mcp_path: "/ingest/mcp" }),
    ]);
  });

  it("rejects duplicate and reserved backend paths", () => {
    const parse = (secondPath: string) => parseConfigText(`
[server]
name = "gateway"
[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"
[backends.one]
mcp_path = "/health"
[backends.one.stdio]
command = "one"
[backends.two]
mcp_path = "${secondPath}"
[backends.two.stdio]
command = "two"
`);
    expect(() => parse("/other/mcp")).toThrow("backend mcp_path is reserved");
    expect(() => parse("/health")).toThrow("backend mcp_path values must be unique");
  });
  it("parses required MVP config", () => {
    const config = parseConfigText(`
[server]
name = "brain"
host = "127.0.0.1"
port = 8787

[stdio]
command = "node"
args = ["server.js"]

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"

[tools]
allow = ["search"]
deny = ["delete_note"]
`);

    expect(config.server.name).toBe("brain");
    expect(config.server.mcp_path).toBe("/mcp");
    expect(config.server.cors).toBeUndefined();
    expect(config.stdio?.command).toBe("node");
    expect(config.auth.mode).toBe("bearer");
    expect(config.tools.allow).toEqual(["search"]);
    expect(config.tools.deny).toEqual(["delete_note"]);
  });

  it("parses allowed CORS origins", () => {
    const config = parseConfigText(`
[server]
name = "brain"

[server.cors]
allowed_origins = ["https://chatgpt.com", "http://localhost:3000"]

[stdio]
command = "node"

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"
`);

    expect(config.server.cors?.allowed_origins).toEqual([
      "https://chatgpt.com",
      "http://localhost:3000",
    ]);
  });

  it("rejects malformed CORS origins", () => {
    const parse = (origin: string) => parseConfigText(`
[server]
name = "brain"

[server.cors]
allowed_origins = ["${origin}"]

[stdio]
command = "node"

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"
`);

    expect(() => parse("https://example.com/path")).toThrow(
      "server.cors.allowed_origins must contain HTTP(S) origins without paths",
    );
    expect(() => parse("ftp://example.com")).toThrow(
      "server.cors.allowed_origins must contain HTTP(S) origins without paths",
    );
    expect(() => parse("not-a-url")).toThrow();
  });

  it("parses a custom mcp path", () => {
    const config = parseConfigText(`
[server]
name = "brain"
mcp_path = "/brain/mcp"

[stdio]
command = "node"

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"
`);

    expect(config.server.mcp_path).toBe("/brain/mcp");
  });

  it("rejects an mcp path without a leading slash", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"
mcp_path = "brain/mcp"

[stdio]
command = "node"

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"
`)).toThrow("server.mcp_path must start with /");
  });

  it("parses oauth protected resource metadata config", () => {
    const config = parseConfigText(`
[server]
name = "brain"
mcp_path = "/brain/mcp"

[stdio]
command = "node"

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"

[oauth.resource]
enabled = true
resource = "https://levitate.example.com/brain/mcp"
authorization_servers = ["https://auth.example.com/"]
scopes_supported = ["levitate:read", "levitate:call"]
`);

    expect(config.oauth.resource.enabled).toBe(true);
    expect(config.oauth.resource.mode).toBe("service");
    expect(config.oauth.resource.resource).toBe("https://levitate.example.com/brain/mcp");
    expect(config.oauth.resource.authorization_servers).toEqual(["https://auth.example.com/"]);
    expect(config.oauth.resource.scopes_supported).toEqual(["levitate:read", "levitate:call"]);
  });

  it("accepts explicit gateway OAuth identity for multiple named backends", () => {
    const config = parseConfigText(`
[server]
name = "gateway"

[auth]
mode = "levitate"

[oauth.resource]
enabled = true
mode = "gateway"
resource = "https://levitate.example.com"
authorization_servers = ["https://levitate.example.com"]
scopes_supported = ["gateway:access"]

[oauth.as]
enabled = true
issuer = "https://levitate.example.com"
subject = "local-user"
allowed_redirect_uri_prefixes = ["https://chatgpt.com/connector/oauth/"]
scopes_supported = ["gateway:access"]
default_scopes = ["gateway:access"]
client_store_file = "state/oauth-clients.json"

[oauth.as.cimd]
enabled = true
allowed_client_id_prefixes = ["https://chatgpt.com/"]

[oauth.as.keys]
private_key_file = "state/oauth-private-key.pem"
key_id = "gateway-key"

[backends.notes]
mcp_path = "/notes/mcp"
[backends.notes.stdio]
command = "notes-mcp"

[backends.ingest]
mcp_path = "/ingest/mcp"
[backends.ingest.stdio]
command = "ingest-mcp"
`);

    expect(config.oauth.resource.mode).toBe("gateway");
    expect(config.oauth.resource.resource).toBe("https://levitate.example.com");
    expect(getBackendConfigs(config)).toHaveLength(2);
  });

  it("parses the runnable gateway OAuth example", () => {
    const config = parseConfigText(readFileSync(
      new URL("../config/oauth-gateway.example.toml", import.meta.url),
      "utf8",
    ));

    expect(config.oauth.resource).toEqual(expect.objectContaining({
      enabled: true,
      mode: "gateway",
      resource: "https://levitate.example.com",
    }));
    expect(config.auth.mode).toBe("levitate");
    expect(getBackendConfigs(config).map((backend) => backend.mcp_path)).toEqual([
      "/notes/mcp",
      "/admin/mcp",
    ]);
  });

  it("rejects service-specific OAuth identity for multiple named backends", () => {
    expect(() => parseConfigText(`
[server]
name = "gateway"

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"

[oauth.resource]
enabled = true
resource = "https://levitate.example.com/notes/mcp"
authorization_servers = ["https://auth.example.com"]

[backends.notes]
mcp_path = "/notes/mcp"
[backends.notes.stdio]
command = "notes-mcp"

[backends.ingest]
mcp_path = "/ingest/mcp"
[backends.ingest.stdio]
command = "ingest-mcp"
`)).toThrow("oauth.resource.mode must be gateway when OAuth metadata protects multiple named backends");
  });

  it("rejects path-scoped resource identifiers in gateway mode", () => {
    expect(() => parseConfigText(`
[server]
name = "gateway"

[stdio]
command = "node"

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"

[oauth.resource]
enabled = true
mode = "gateway"
resource = "https://levitate.example.com/notes/mcp"
authorization_servers = ["https://auth.example.com"]
`)).toThrow("oauth.resource.resource must be an origin without a path in gateway mode");
  });

  it("rejects one metadata URL override in gateway mode", () => {
    expect(() => parseConfigText(`
[server]
name = "gateway"

[stdio]
command = "node"

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"

[oauth.resource]
enabled = true
mode = "gateway"
resource = "https://levitate.example.com"
authorization_servers = ["https://auth.example.com"]
metadata_url = "https://levitate.example.com/.well-known/oauth-protected-resource"
`)).toThrow("oauth.resource.metadata_url cannot override per-backend metadata URLs in gateway mode");
  });

  it("rejects enabled oauth protected resource metadata without a resource", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"

[oauth.resource]
enabled = true
authorization_servers = ["https://auth.example.com/"]
`)).toThrow("oauth.resource.resource is required when oauth.resource.enabled is true");
  });

  it("rejects enabled oauth protected resource metadata without authorization servers", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"

[oauth.resource]
enabled = true
resource = "https://levitate.example.com/brain/mcp"
`)).toThrow("oauth.resource.authorization_servers must be non-empty when oauth.resource.enabled is true");
  });

  it("rejects oauth protected resource metadata urls without https", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"

[oauth.resource]
enabled = true
resource = "http://levitate.example.com/brain/mcp"
authorization_servers = ["https://auth.example.com/"]
`)).toThrow("OIDC URLs must use https");

    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"

[oauth.resource]
enabled = true
resource = "https://levitate.example.com/brain/mcp"
authorization_servers = ["http://auth.example.com/"]
`)).toThrow("OIDC URLs must use https");

    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"

[oauth.resource]
enabled = true
resource = "https://levitate.example.com/brain/mcp"
authorization_servers = ["https://auth.example.com/"]
metadata_url = "http://levitate.example.com/.well-known/oauth-protected-resource"
`)).toThrow("OIDC URLs must use https");
  });

  it.each([
    "https://levitate.example.com/brain/%20/mcp",
    "https://levitate.example.com/brain/*/mcp",
    "https://levitate.example.com/brain/:service/mcp",
  ])("rejects oauth resource paths that cannot be matched literally: %s", (resource) => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "bearer"
token_env = "LEVITATE_TOKEN"

[oauth.resource]
enabled = true
resource = "${resource}"
authorization_servers = ["https://auth.example.com/"]
`)).toThrow("oauth.resource.resource must use literal URL-safe path segments without query or fragment");
  });

  it("parses oauth authorization server config", () => {
    const config = parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "levitate"

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
allowed_redirect_uri_prefixes = ["https://chatgpt.com/connector/oauth/"]
scopes_supported = ["brain:read", "brain:write"]
default_scopes = ["brain:read"]
client_store_file = "state/oauth-clients.json"

[oauth.as.keys]
private_key_file = "state/oauth-private-key.pem"
key_id = "levitate-local-1"

[oauth.as.dcr]
enabled = true

[oauth.as.cimd]
enabled = true
allowed_client_id_prefixes = ["https://chatgpt.com/oauth/"]
`);

    expect(config.oauth.as.cimd).toEqual({
      enabled: true,
      allowed_client_id_prefixes: ["https://chatgpt.com/oauth/"],
    });

    expect(config.auth.mode).toBe("levitate");
    expect(config.oauth.as.enabled).toBe(true);
    expect(config.oauth.as.dcr.enabled).toBe(true);
    expect(config.oauth.as.issuer).toBe("https://levitate.example.com");
    expect(config.oauth.as.access_token_ttl_seconds).toBe(3600);
    expect(config.oauth.as.authorization_code_ttl_seconds).toBe(300);
  });

  it("rejects enabled oauth authorization server without required config", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "levitate"

[oauth.as]
enabled = true
`)).toThrow("oauth.as.issuer is required when oauth.as.enabled is true");
  });

  it("rejects CIMD without an allowed client ID prefix", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "levitate"

[oauth.resource]
enabled = true
resource = "https://levitate.example.com/brain/mcp"
authorization_servers = ["https://levitate.example.com"]
scopes_supported = ["brain:read"]

[oauth.as]
enabled = true
issuer = "https://levitate.example.com"
subject = "local-user"
allowed_redirect_uri_prefixes = ["https://chatgpt.com/connector/oauth/"]
scopes_supported = ["brain:read"]
default_scopes = ["brain:read"]
client_store_file = "state/oauth-clients.json"

[oauth.as.cimd]
enabled = true

[oauth.as.keys]
private_key_file = "state/oauth-private-key.pem"
key_id = "levitate-local-1"
`)).toThrow("oauth.as.cimd.allowed_client_id_prefixes must be non-empty when oauth.as.cimd.enabled is true");
  });

  it("rejects oauth authorization server default scopes outside supported scopes", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "levitate"

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
allowed_redirect_uri_prefixes = ["https://chatgpt.com/connector/oauth/"]
scopes_supported = ["brain:read"]
default_scopes = ["brain:write"]
client_store_file = "state/oauth-clients.json"

[oauth.as.keys]
private_key_file = "state/oauth-private-key.pem"
key_id = "levitate-local-1"
`)).toThrow("oauth.as.default_scopes must be a subset of oauth.as.scopes_supported");
  });

  it("parses manual oauth authorization approval mode", () => {
    const config = parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "levitate"

[oauth.resource]
enabled = true
resource = "https://levitate.example.com/brain/mcp"
authorization_servers = ["https://levitate.example.com"]
scopes_supported = ["brain:read"]

[oauth.as]
enabled = true
issuer = "https://levitate.example.com"
subject = "local-user"
approval = "manual"
approval_secret_env = "LEVITATE_APPROVAL_SECRET"
allowed_redirect_uri_prefixes = ["https://chatgpt.com/connector/oauth/"]
scopes_supported = ["brain:read"]
default_scopes = ["brain:read"]
client_store_file = "state/oauth-clients.json"

[oauth.as.keys]
private_key_file = "state/oauth-private-key.pem"
key_id = "levitate-local-1"
`);

    expect(config.oauth.as.approval).toBe("manual");
  });

  it("rejects manual oauth authorization approval mode without approval secret env", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "levitate"

[oauth.resource]
enabled = true
resource = "https://levitate.example.com/brain/mcp"
authorization_servers = ["https://levitate.example.com"]
scopes_supported = ["brain:read"]

[oauth.as]
enabled = true
issuer = "https://levitate.example.com"
subject = "local-user"
approval = "manual"
allowed_redirect_uri_prefixes = ["https://chatgpt.com/connector/oauth/"]
scopes_supported = ["brain:read"]
default_scopes = ["brain:read"]
client_store_file = "state/oauth-clients.json"

[oauth.as.keys]
private_key_file = "state/oauth-private-key.pem"
key_id = "levitate-local-1"
`)).toThrow("oauth.as.approval_secret_env is required when oauth.as.approval is manual");
  });

  it("rejects oauth resource metadata without authorization server issuer", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "levitate"

[oauth.resource]
enabled = true
resource = "https://levitate.example.com/brain/mcp"
authorization_servers = ["https://auth.example.com"]
scopes_supported = ["brain:read"]

[oauth.as]
enabled = true
issuer = "https://levitate.example.com"
subject = "local-user"
approval = "auto"
allowed_redirect_uri_prefixes = ["https://chatgpt.com/connector/oauth/"]
scopes_supported = ["brain:read"]
default_scopes = ["brain:read"]
client_store_file = "state/oauth-clients.json"

[oauth.as.keys]
private_key_file = "state/oauth-private-key.pem"
key_id = "levitate-local-1"
`)).toThrow("oauth.resource.authorization_servers must include oauth.as.issuer when both are enabled");
  });

  it("rejects levitate auth mode without enabled oauth authorization server", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "levitate"
`)).toThrow("oauth.as.enabled is required when auth.mode is levitate");
  });

  it("rejects levitate auth mode without oauth resource", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "levitate"

[oauth.as]
enabled = true
issuer = "https://levitate.example.com"
subject = "local-user"
approval = "auto"
allowed_redirect_uri_prefixes = ["https://chatgpt.com/connector/oauth/"]
scopes_supported = ["brain:read"]
default_scopes = ["brain:read"]
client_store_file = "state/oauth-clients.json"

[oauth.as.keys]
private_key_file = "state/oauth-private-key.pem"
key_id = "levitate-local-1"
`)).toThrow("oauth.resource.resource is required when auth.mode is levitate");
  });

  it("rejects bearer auth without token source", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "bearer"
`)).toThrow();
  });

  it("parses oidc auth config", () => {
    const config = parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "oidc"
issuer = "https://auth.example.test/"
audience = "https://levitate.example.test"
jwks_uri = "https://auth.example.test/.well-known/jwks.json"
allowed_subjects = ["client-id@clients"]
`);

    expect(config.auth.mode).toBe("oidc");
    if (config.auth.mode === "oidc") {
      expect(config.auth.jwks_uri).toBe("https://auth.example.test/.well-known/jwks.json");
      expect(config.auth.allowed_subjects).toEqual(["client-id@clients"]);
    }
  });

  it("rejects oidc issuer without https", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "oidc"
issuer = "http://auth.example.test/"
audience = "https://levitate.example.test"
jwks_uri = "https://auth.example.test/.well-known/jwks.json"
`)).toThrow("OIDC URLs must use https");
  });

  it("rejects oidc jwks uri without https", () => {
    expect(() => parseConfigText(`
[server]
name = "brain"

[stdio]
command = "node"

[auth]
mode = "oidc"
issuer = "https://auth.example.test/"
audience = "https://levitate.example.test"
jwks_uri = "http://auth.example.test/.well-known/jwks.json"
`)).toThrow("OIDC URLs must use https");
  });
});
