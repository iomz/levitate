import type { Tool } from "@modelcontextprotocol/sdk/types.js";

export interface ToolPolicy {
  allow?: string[];
  deny: string[];
}

export function isToolAllowed(name: string, policy: ToolPolicy): boolean {
  if (policy.allow && !policy.allow.includes(name)) return false;
  if (policy.deny.includes(name)) return false;
  return true;
}

export function filterTools<T extends Pick<Tool, "name">>(
  tools: T[],
  policy: ToolPolicy,
): T[] {
  return tools.filter((tool) => isToolAllowed(tool.name, policy));
}

export function deniedReason(name: string, policy: ToolPolicy): string | undefined {
  if (policy.allow && !policy.allow.includes(name)) return "tool not in allowlist";
  if (policy.deny.includes(name)) return "tool in denylist";
  return undefined;
}
