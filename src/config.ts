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

const HttpsUrlSchema = z.string().url().refine(
  (value) => new URL(value).protocol === "https:",
  "OIDC URLs must use https",
);

const OAuthResourceSchema = z.object({
  enabled: z.boolean().default(false),
  resource: HttpsUrlSchema.optional(),
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
  approval: z.literal("auto").optional(),
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

  if (value.approval !== "auto") {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "oauth.as.approval must be auto when oauth.as.enabled is true",
      path: ["approval"],
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

const ConfigSchema = z.object({
  server: z.object({
    name: z.string().min(1),
    host: z.string().min(1).default("127.0.0.1"),
    port: z.coerce.number().int().positive().max(65535).default(8787),
    log_level: z.enum(["debug", "info", "warn", "error"]).default("info"),
    mcp_path: McpPathSchema.default("/mcp"),
  }),
  stdio: z.object({
    command: z.string().min(1),
    args: z.array(z.string()).default([]),
    cwd: z.string().min(1).optional(),
  }),
  env: z.record(z.string()).default({}),
  instructions: z.object({
    text: z.string().optional(),
    file: z.string().min(1).optional(),
  }).default({}),
  auth: AuthSchema,
  oauth: z.object({
    resource: OAuthResourceSchema.default({ enabled: false }),
    as: OAuthAuthorizationServerSchema.default({ enabled: false }),
  }).default({ resource: { enabled: false }, as: { enabled: false } }),
  tools: z.object({
    allow: z.array(z.string().min(1)).optional(),
    deny: z.array(z.string().min(1)).default([]),
  }).default({ deny: [] }),
}).superRefine((value, context) => {
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
