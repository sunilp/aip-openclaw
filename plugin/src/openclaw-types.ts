/**
 * Minimal type definitions for OpenClaw Plugin SDK.
 * These match the plugin-sdk/plugin-entry API without requiring the full openclaw package.
 */

export interface PluginAPI {
  registerHook(event: string, handler: HookHandler): void;
  registerTool(definition: ToolDefinition, options?: { optional?: boolean }): void;
  getConfig(): Record<string, unknown>;
}

export type HookHandler = (context: HookContext) => Promise<HookResult | void> | HookResult | void;

export interface HookContext {
  toolName?: string;
  toolArgs?: Record<string, unknown>;
  headers?: Record<string, string>;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface HookResult {
  block?: boolean;
  requireApproval?: boolean;
  reason?: string;
}

export interface ToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  execute: (id: string, params: Record<string, unknown>) => Promise<ToolResult>;
}

export interface ToolResult {
  content: Array<{ type: string; text: string }>;
}

export interface PluginEntry {
  id: string;
  name: string;
  description: string;
  register(api: PluginAPI): void;
}
