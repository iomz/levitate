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
import type { LevitateConfig } from "../config.js";
import type { Logger } from "../logging.js";

export class StdioMcpBackend {
  private readonly client = new Client(
    { name: "levitate-backend-client", version: "0.1.0" },
    { capabilities: {} },
  );
  private transport?: StdioClientTransport;

  constructor(
    private readonly config: LevitateConfig,
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
    await this.transport?.close();
  }
}
