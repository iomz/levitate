import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parse } from "smol-toml";
import { z } from "zod";

const BearerAuthSchema = z.object({
    mode: z.literal("bearer"),
    token: z.string().min(1).optional(),
    token_env: z.string().min(1).optional(),
  });

const AuthSchema = z.union([
  BearerAuthSchema,
  z.object({
    mode: z.literal("oidc"),
    issuer: z.string().url(),
    audience: z.string().min(1),
    jwks_url: z.string().url().optional(),
    allowed_subjects: z.array(z.string().min(1)).default([]),
    allowed_emails: z.array(z.string().email()).default([]),
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
  tools: z.object({
    allow: z.array(z.string().min(1)).optional(),
    deny: z.array(z.string().min(1)).default([]),
  }).default({ deny: [] }),
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
