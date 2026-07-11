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

  async listTools(): Promise<ListToolsResult> {
    return this.client.listTools();
  }

  async callTool(params: CallToolRequest["params"]): Promise<CallToolResult> {
    return this.client.callTool(params) as Promise<CallToolResult>;
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
