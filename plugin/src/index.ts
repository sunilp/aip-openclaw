/**
 * AIP Guard - Native OpenClaw Plugin
 *
 * Hooks into before_tool_call to verify AIP delegation tokens
 * and enforce capability policies on every tool execution.
 */

import { KeyPair } from "@aip-sdk/core";
import { CompactToken, TokenError } from "@aip-sdk/token";
import type { PluginEntry, PluginAPI, HookContext, HookResult } from "./openclaw-types.js";

interface AipGuardConfig {
  trustKeys?: string[];
  unsignedSkills?: "warn" | "block" | "allow";
  auditLog?: string;
}

interface AuditEntry {
  ts: string;
  decision: "allow" | "deny" | "warn";
  tool: string | undefined;
  subject: string | null;
  reason: string;
}

function logAudit(entry: AuditEntry, auditPath?: string): void {
  const line = JSON.stringify(entry);
  console.error(line);
  if (auditPath) {
    // Dynamic import to avoid bundling fs for non-Node environments
    import("node:fs").then(({ appendFileSync }) => {
      appendFileSync(auditPath, line + "\n");
    }).catch(() => {});
  }
}

async function verifyToken(
  tokenStr: string,
  trustKeys: string[]
): Promise<CompactToken | null> {
  for (const multibaseKey of trustKeys) {
    try {
      const pubBytes = KeyPair.decodeMultibase(multibaseKey);
      return await CompactToken.verify(tokenStr, pubBytes);
    } catch {
      continue;
    }
  }
  return null;
}

function extractToken(context: HookContext): string | null {
  // Check headers
  if (context.headers) {
    const key = Object.keys(context.headers).find(
      (k) => k.toLowerCase() === "x-aip-token"
    );
    if (key) return context.headers[key];
  }
  // Check metadata (A2A style)
  if (context.metadata && typeof context.metadata.aip_token === "string") {
    return context.metadata.aip_token;
  }
  return null;
}

const aipGuard: PluginEntry = {
  id: "aip-guard",
  name: "AIP Guard",
  description: "Delegation verification and capability enforcement for tool calls",

  register(api: PluginAPI) {
    const config = api.getConfig() as AipGuardConfig;
    const trustKeys = config.trustKeys ?? [];
    const unsignedPolicy = config.unsignedSkills ?? "warn";
    const auditPath = config.auditLog;

    api.registerHook("before_tool_call", async (context: HookContext): Promise<HookResult | void> => {
      const toolName = context.toolName;
      const tokenStr = extractToken(context);

      // No token present
      if (!tokenStr) {
        const entry: AuditEntry = {
          ts: new Date().toISOString(),
          decision: unsignedPolicy === "block" ? "deny" : "warn",
          tool: toolName,
          subject: null,
          reason: "no_aip_token",
        };
        logAudit(entry, auditPath);

        if (unsignedPolicy === "block") {
          return { block: true, reason: "No AIP token. Blocked by policy." };
        }
        if (unsignedPolicy === "warn") {
          console.error(`[aip-guard] WARNING: tool call "${toolName}" has no AIP token`);
        }
        return; // allow
      }

      // No trust keys configured
      if (trustKeys.length === 0) {
        logAudit({
          ts: new Date().toISOString(),
          decision: "warn",
          tool: toolName,
          subject: null,
          reason: "no_trust_keys_configured",
        }, auditPath);
        return; // can't verify without trust keys, pass through
      }

      // Verify token
      const verified = await verifyToken(tokenStr, trustKeys);

      if (!verified) {
        logAudit({
          ts: new Date().toISOString(),
          decision: "deny",
          tool: toolName,
          subject: null,
          reason: "signature_invalid",
        }, auditPath);
        return { block: true, reason: "AIP token signature verification failed." };
      }

      // Check scope
      const claims = verified.claims;
      const requiredScope = toolName ? `tool:${toolName}` : null;

      if (requiredScope && !verified.hasScope(requiredScope)) {
        logAudit({
          ts: new Date().toISOString(),
          decision: "deny",
          tool: toolName,
          subject: claims.sub,
          reason: `scope_insufficient: ${requiredScope} not in token scope [${claims.scope.join(", ")}]`,
        }, auditPath);
        return {
          block: true,
          reason: `AIP scope insufficient: ${requiredScope} not authorized.`,
        };
      }

      // Check expiry (CompactToken.verify already checks, but belt-and-suspenders)
      const now = Math.floor(Date.now() / 1000);
      if (claims.exp < now) {
        logAudit({
          ts: new Date().toISOString(),
          decision: "deny",
          tool: toolName,
          subject: claims.sub,
          reason: "token_expired",
        }, auditPath);
        return { block: true, reason: "AIP token has expired." };
      }

      // Allowed
      logAudit({
        ts: new Date().toISOString(),
        decision: "allow",
        tool: toolName,
        subject: claims.sub,
        reason: "valid_token_scope_verified",
      }, auditPath);

      // Don't return anything = allow the tool call
    });

    // Register utility tools for the LLM to query security status
    api.registerTool(
      {
        name: "aip_security_status",
        description: "Show AIP Guard security status: configured trust keys and policy",
        parameters: {},
        async execute() {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    trust_keys: trustKeys.length,
                    unsigned_policy: unsignedPolicy,
                    audit_log: auditPath ?? "stderr only",
                  },
                  null,
                  2
                ),
              },
            ],
          };
        },
      },
      { optional: true }
    );
  },
};

export default aipGuard;
