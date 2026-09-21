import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  getDefaultEnvironment,
  StdioClientTransport,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import type {
  CallToolRequest,
  CallToolResult,
  ListToolsResult,
} from "@modelcontextprotocol/sdk/types.js";
import type { BackendConfig } from "../config.js";
import type { Logger } from "../logging.js";
import { PRINCIPAL_META_KEY, stripReservedMeta } from "./meta.js";
import type { Principal } from "../auth/principal.js";

export class StdioMcpBackend {
  private readonly client = new Client(
    { name: "levitate-backend-client", version: "0.1.0" },
    { capabilities: {} },
  );
  private transport?: StdioClientTransport;
  private ready = false;
  private closing = false;

  constructor(
    private readonly config: BackendConfig,
    private readonly logger: Logger,
  ) {}

  async start(): Promise<void> {
    const env = {
      ...getDefaultEnvironment(),
      ...this.config.env,
    };

    this.transport = new StdioClientTransport({
      command: this.config.stdio.command,
      args: this.config.stdio.args,
      cwd: this.config.stdio.cwd,
      env,
      stderr: "pipe",
    });

    this.transport.stderr?.on("data", (chunk) => {
      this.logger.warn("backend stderr", { data: chunk.toString().trimEnd() });
    });

    this.logger.info("backend process starting", {
      command: this.config.stdio.command,
      args: this.config.stdio.args,
    });

    await this.client.connect(this.transport);
    const clientOnClose = this.transport.onclose;
    const pid = this.transport.pid;
    this.transport.onclose = () => {
      this.ready = false;
      const fields = { pid, expected: this.closing };
      if (this.closing) {
        this.logger.info("backend process stopped", fields);
      } else {
        this.logger.error("backend process stopped unexpectedly", fields);
      }
      clientOnClose?.();
    };
    this.ready = true;

    this.logger.info("backend process started", {
      pid: this.transport.pid,
    });
  }

  getInstructions(): string | undefined {
    return this.client.getInstructions();
  }

  async listTools(): Promise<ListToolsResult> {
    // No client-supplied params are forwarded here. Anything added later must
    // pass through stripReservedMeta first.
    return this.client.listTools();
  }

  async callTool(
    params: CallToolRequest["params"],
    principal?: Principal,
  ): Promise<CallToolResult> {
    // principal.enabled is an operator statement that this backend receives an
    // authenticated principal. If Levitate cannot fulfil it, the call is
    // refused rather than degraded to a principal-less one: silently
    // proceeding would make the enabled and disabled states indistinguishable
    // at the backend, and would rest a gateway invariant on every backend
    // author implementing their half of it. Enforced here, at the process
    // boundary, so a future call path cannot omit it.
    if (this.config.principal.enabled && !principal) {
      this.logger.error("refusing tool call without an asserted principal", {
        backend: this.config.id,
        tool: params.name,
      });
      return {
        content: [{
          type: "text",
          text: `Levitate refused tool call: ${params.name} (principal required)`,
        }],
        isError: true,
      };
    }

    // Sanitizing here rather than in the proxy keeps the rule at the process
    // boundary, so it covers every request forwarded to the backend including
    // any handler added later.
    const { params: sanitized, strippedKeys } = stripReservedMeta(params);
    if (strippedKeys.length) {
      this.logger.warn("stripped reserved metadata from request", {
        backend: this.config.id,
        tool: params.name,
        keys: strippedKeys,
      });
    }

    // Injection happens after stripping, never before, so a client-supplied
    // value under the principal key is replaced rather than merged with. The
    // two steps live together because that ordering is the whole guarantee.
    const forwarded = principal
      ? attachPrincipal(sanitized, principal)
      : sanitized;
    if (principal) {
      this.logger.info("principal asserted to backend", {
        backend: this.config.id,
        tool: params.name,
        auth_kind: principal.auth_kind,
        subject_type: principal.subject_type,
        subject: principal.subject,
        client_id: principal.client_id,
      });
    }
    return this.client.callTool(forwarded) as Promise<CallToolResult>;
  }

  async close(): Promise<void> {
    this.closing = true;
    this.ready = false;
    await this.transport?.close();
  }

  isReady(): boolean {
    return this.ready;
  }
}

/**
 * Returns a copy carrying the principal. stripReservedMeta returns the caller's
 * own object when it had nothing to remove, so building new objects here is
 * what keeps this from mutating a request the proxy still owns.
 */
function attachPrincipal(
  params: CallToolRequest["params"],
  principal: Principal,
): CallToolRequest["params"] {
  return {
    ...params,
    _meta: { ...params._meta, [PRINCIPAL_META_KEY]: principal },
  };
}
