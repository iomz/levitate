import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parse } from "smol-toml";
import { z } from "zod";

const BearerAuthSchema = z.object({
    mode: z.literal("bearer"),
    token: z.string().min(1).optional(),
    token_env: z.string().min(1).optional(),
  });

const McpPathSchema = z.string().min(1).refine(
  (value) => value.startsWith("/"),
  "server.mcp_path must start with /",
);

const CorsOriginSchema = z.string().url().refine((value) => {
  const url = new URL(value);
  return (
    (url.protocol === "http:" || url.protocol === "https:") &&
    value === url.origin
  );
}, "server.cors.allowed_origins must contain HTTP(S) origins without paths");

const HttpsUrlSchema = z.string().url().refine(
  (value) => new URL(value).protocol === "https:",
  "OIDC URLs must use https",
);

const OAuthResourceUrlSchema = HttpsUrlSchema.refine((value) => {
  const url = new URL(value);
  return (
    !url.search &&
    !url.hash &&
    /^\/(?:[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*\/?)?$/.test(url.pathname)
  );
}, "oauth.resource.resource must use literal URL-safe path segments without query or fragment");

const CimdClientIdPrefixSchema = HttpsUrlSchema.refine((value) => {
  const url = new URL(value);
  return !url.username && !url.password && !url.search && !url.hash;
}, "oauth.as.cimd.allowed_client_id_prefixes must not contain credentials, query strings, or fragments");

const OAuthResourceSchema = z.object({
  enabled: z.boolean().default(false),
  resource: OAuthResourceUrlSchema.optional(),
  authorization_servers: z.array(HttpsUrlSchema).default([]),
  scopes_supported: z.array(z.string().min(1)).default([]),
  metadata_url: HttpsUrlSchema.optional(),
}).superRefine((value, context) => {
  if (!value.enabled) return;

  if (!value.resource) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.resource.resource is required when oauth.resource.enabled is true",
      path: ["resource"],
    });
  }

  if (!value.authorization_servers.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.resource.authorization_servers must be non-empty when oauth.resource.enabled is true",
      path: ["authorization_servers"],
    });
  }
});

const OAuthAuthorizationServerSchema = z.object({
  enabled: z.boolean().default(false),
  issuer: HttpsUrlSchema.optional(),
  subject: z.string().min(1).optional(),
  approval: z.enum(["auto", "manual"]).default("auto"),
  approval_secret_env: z.string().min(1).optional(),
  dcr: z.object({
    enabled: z.boolean().default(false),
  }).default({ enabled: false }),
  cimd: z.object({
    enabled: z.boolean().default(false),
    allowed_client_id_prefixes: z.array(CimdClientIdPrefixSchema).default([]),
  }).default({ enabled: false, allowed_client_id_prefixes: [] }),
  rate_limits: z.object({
    window_seconds: z.coerce.number().int().positive().default(60),
    registration: z.coerce.number().int().positive().default(10),
    authorization: z.coerce.number().int().positive().default(30),
    token: z.coerce.number().int().positive().default(60),
    approval: z.coerce.number().int().positive().default(10),
  }).optional(),
  allowed_redirect_uri_prefixes: z.array(HttpsUrlSchema).default([]),
  scopes_supported: z.array(z.string().min(1)).default([]),
  default_scopes: z.array(z.string().min(1)).default([]),
  access_token_ttl_seconds: z.coerce.number().int().positive().default(3600),
  authorization_code_ttl_seconds: z.coerce.number().int().positive().default(300),
  client_store_file: z.string().min(1).optional(),
  keys: z.object({
    private_key_file: z.string().min(1).optional(),
    key_id: z.string().min(1).optional(),
  }).default({}),
}).superRefine((value, context) => {
  if (!value.enabled) return;

  if (!value.issuer) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.as.issuer is required when oauth.as.enabled is true",
      path: ["issuer"],
    });
  }

  if (!value.subject) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.as.subject is required when oauth.as.enabled is true",
      path: ["subject"],
    });
  }

  if (value.approval === "manual" && !value.approval_secret_env) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.as.approval_secret_env is required when oauth.as.approval is manual",
      path: ["approval_secret_env"],
    });
  }

  if (!value.allowed_redirect_uri_prefixes.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.as.allowed_redirect_uri_prefixes must be non-empty when oauth.as.enabled is true",
      path: ["allowed_redirect_uri_prefixes"],
    });
  }

  if (!value.scopes_supported.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.as.scopes_supported must be non-empty when oauth.as.enabled is true",
      path: ["scopes_supported"],
    });
  }

  if (!value.default_scopes.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.as.default_scopes must be non-empty when oauth.as.enabled is true",
      path: ["default_scopes"],
    });
  }

  if (value.cimd.enabled && !value.cimd.allowed_client_id_prefixes.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.as.cimd.allowed_client_id_prefixes must be non-empty when oauth.as.cimd.enabled is true",
      path: ["cimd", "allowed_client_id_prefixes"],
    });
  }

  const unsupportedDefaultScopes = value.default_scopes.filter((scope) => !value.scopes_supported.includes(scope));
  if (unsupportedDefaultScopes.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.as.default_scopes must be a subset of oauth.as.scopes_supported",
      path: ["default_scopes"],
    });
  }

  if (!value.client_store_file) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.as.client_store_file is required when oauth.as.enabled is true",
      path: ["client_store_file"],
    });
  }

  if (!value.keys.private_key_file) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.as.keys.private_key_file is required when oauth.as.enabled is true",
      path: ["keys", "private_key_file"],
    });
  }

  if (!value.keys.key_id) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.as.keys.key_id is required when oauth.as.enabled is true",
      path: ["keys", "key_id"],
    });
  }
});

const AuthSchema = z.union([
  BearerAuthSchema,
  z.object({
    mode: z.literal("oidc"),
    issuer: HttpsUrlSchema,
    audience: z.string().min(1),
    jwks_uri: HttpsUrlSchema.optional(),
    allowed_subjects: z.array(z.string().min(1)).default([]),
    allowed_emails: z.array(z.string().email()).default([]),
  }),
  z.object({
    mode: z.literal("levitate"),
  }),
]).superRefine((value, context) => {
  if (value.mode === "bearer" && !value.token && !value.token_env) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "auth.token or auth.token_env is required for bearer auth",
      path: ["token_env"],
    });
  }
});

const StdioSchema = z.object({
  command: z.string().min(1),
  args: z.array(z.string()).default([]),
  cwd: z.string().min(1).optional(),
});

const InstructionsSchema = z.object({
  text: z.string().optional(),
  file: z.string().min(1).optional(),
}).default({});

const ToolsSchema = z.object({
  allow: z.array(z.string().min(1)).optional(),
  deny: z.array(z.string().min(1)).default([]),
}).default({ deny: [] });

const NamedBackendSchema = z.object({
  name: z.string().min(1).optional(),
  mcp_path: McpPathSchema,
  stdio: StdioSchema,
  env: z.record(z.string()).default({}),
  instructions: InstructionsSchema,
  tools: ToolsSchema,
});

const ConfigSchema = z.object({
  server: z.object({
    name: z.string().min(1),
    host: z.string().min(1).default("127.0.0.1"),
    port: z.coerce.number().int().positive().max(65535).default(8787),
    log_level: z.enum(["debug", "info", "warn", "error"]).default("info"),
    mcp_path: McpPathSchema.default("/mcp"),
    cors: z.object({
      allowed_origins: z.array(CorsOriginSchema).min(1),
    }).optional(),
  }),
  stdio: StdioSchema.optional(),
  backends: z.record(NamedBackendSchema).optional(),
  env: z.record(z.string()).default({}),
  instructions: InstructionsSchema,
  auth: AuthSchema,
  oauth: z.object({
    resource: OAuthResourceSchema.default({ enabled: false }),
    as: OAuthAuthorizationServerSchema.default({ enabled: false }),
  }).default({ resource: { enabled: false }, as: { enabled: false } }),
  tools: ToolsSchema,
}).superRefine((value, context) => {
  const backendEntries = Object.entries(value.backends ?? {});
  if (!value.stdio && !backendEntries.length) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "stdio or backends must configure at least one backend", path: ["backends"] });
  }
  if (value.stdio && value.backends !== undefined) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "stdio and backends cannot be configured together", path: ["backends"] });
  }
  const paths = backendEntries.map(([, backend]) => backend.mcp_path);
  if (new Set(paths).size !== paths.length) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "backend mcp_path values must be unique", path: ["backends"] });
  }
  for (const path of paths) {
    if (["/health", "/ready"].includes(path) || path.startsWith("/oauth") || path.startsWith("/.well-known")) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: `backend mcp_path is reserved: ${path}`, path: ["backends"] });
    }
  }
  if (value.stdio) {
    const path = value.server.mcp_path;
    if (["/health", "/ready"].includes(path) || path.startsWith("/oauth") || path.startsWith("/.well-known")) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: `backend mcp_path is reserved: ${path}`, path: ["server", "mcp_path"] });
    }
  }
  if (backendEntries.length > 1 && value.oauth.resource.enabled) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "oauth.resource is currently supported only with one backend", path: ["oauth", "resource"] });
  }
  if (backendEntries.length > 1 && value.auth.mode === "levitate") {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "auth.mode levitate is currently supported only with one backend", path: ["auth", "mode"] });
  }
  if (value.auth.mode === "levitate" && !value.oauth.as.enabled) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.as.enabled is required when auth.mode is levitate",
      path: ["auth", "mode"],
    });
  }

  if (value.auth.mode === "levitate" && !value.oauth.resource.resource) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.resource.resource is required when auth.mode is levitate",
      path: ["oauth", "resource", "resource"],
    });
  }

  if (value.oauth.resource.enabled && value.oauth.as.enabled) {
    const issuer = value.oauth.as.issuer;
    if (issuer && !value.oauth.resource.authorization_servers.includes(issuer)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "oauth.resource.authorization_servers must include oauth.as.issuer when both are enabled",
        path: ["oauth", "resource", "authorization_servers"],
      });
    }
  }
});

export type LevitateConfig = z.infer<typeof ConfigSchema>;
export type AuthConfig = LevitateConfig["auth"];
export interface BackendConfig {
  id: string;
  name: string;
  mcp_path: string;
  stdio: z.infer<typeof StdioSchema>;
  env: Record<string, string>;
  instructions: z.infer<typeof InstructionsSchema>;
  tools: z.infer<typeof ToolsSchema>;
}

export function getBackendConfigs(config: LevitateConfig): BackendConfig[] {
  if (config.backends) {
    return Object.entries(config.backends).map(([id, backend]) => ({
      id,
      name: backend.name ?? id,
      mcp_path: backend.mcp_path,
      stdio: backend.stdio,
      env: backend.env,
      instructions: backend.instructions,
      tools: backend.tools,
    }));
  }
  if (!config.stdio) throw new Error("stdio backend configuration missing");
  return [{ id: "default", name: config.server.name, mcp_path: config.server.mcp_path, stdio: config.stdio, env: config.env, instructions: config.instructions, tools: config.tools }];
}

export function parseConfigText(text: string): LevitateConfig {
  return ConfigSchema.parse(parse(text));
}

export async function loadConfig(path: string): Promise<LevitateConfig> {
  const configPath = resolve(path);
  const text = await readFile(configPath, "utf8");
  return parseConfigText(text);
}

export function resolveBearerToken(auth: AuthConfig): string {
  if (auth.mode !== "bearer") {
    throw new Error(`auth mode ${auth.mode} is not implemented yet`);
  }

  if (auth.token) return auth.token;

  const token = process.env[auth.token_env ?? ""];
  if (!token) {
    throw new Error(`missing bearer token env ${auth.token_env}`);
  }
  return token;
}

export function getConfigPath(argv = process.argv, env = process.env): string {
  const configFlagIndex = argv.findIndex((arg) => arg === "--config" || arg === "-c");
  if (configFlagIndex >= 0 && argv[configFlagIndex + 1]) {
    return argv[configFlagIndex + 1];
  }

  if (env.LEVITATE_CONFIG) return env.LEVITATE_CONFIG;
  return "config/fake-stdio.toml";
}
