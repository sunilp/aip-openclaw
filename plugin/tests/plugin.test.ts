import { describe, it, expect, vi, beforeEach } from "vitest";
import { KeyPair } from "@aip-sdk/core";
import { CompactToken } from "@aip-sdk/token";
import aipGuard from "../src/index.js";
import type { PluginAPI, HookContext, HookHandler, HookResult } from "../src/openclaw-types.js";

// Mock PluginAPI that captures registered hooks
function createMockAPI(config: Record<string, unknown> = {}): {
  api: PluginAPI;
  hooks: Map<string, HookHandler>;
} {
  const hooks = new Map<string, HookHandler>();
  const api: PluginAPI = {
    registerHook(event: string, handler: HookHandler) {
      hooks.set(event, handler);
    },
    registerTool() {},
    getConfig() {
      return config;
    },
  };
  return { api, hooks };
}

function makeToken(kp: KeyPair, scope: string[]): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return CompactToken.create(
    {
      iss: `aip:key:ed25519:${kp.publicKeyMultibase()}`,
      sub: `aip:key:ed25519:${kp.publicKeyMultibase()}`,
      scope,
      max_depth: 0,
      iat: now,
      exp: now + 3600,
    },
    kp
  );
}

describe("AIP Guard Plugin", () => {
  it("registers before_tool_call hook", () => {
    const { api, hooks } = createMockAPI();
    aipGuard.register(api);
    expect(hooks.has("before_tool_call")).toBe(true);
  });

  it("allows tool call with valid token and matching scope", async () => {
    const kp = await KeyPair.generate();
    const { api, hooks } = createMockAPI({
      trustKeys: [kp.publicKeyMultibase()],
    });
    aipGuard.register(api);

    const handler = hooks.get("before_tool_call")!;
    const token = await makeToken(kp, ["tool:search"]);
    const result = await handler({
      toolName: "search",
      headers: { "X-AIP-Token": token },
    });

    // No result = allow
    expect(result).toBeUndefined();
  });

  it("blocks tool call with invalid signature", async () => {
    const kp1 = await KeyPair.generate();
    const kp2 = await KeyPair.generate();
    const { api, hooks } = createMockAPI({
      trustKeys: [kp2.publicKeyMultibase()], // trust kp2 but token signed by kp1
    });
    aipGuard.register(api);

    const handler = hooks.get("before_tool_call")!;
    const token = await makeToken(kp1, ["tool:search"]);
    const result = (await handler({
      toolName: "search",
      headers: { "X-AIP-Token": token },
    })) as HookResult;

    expect(result.block).toBe(true);
    expect(result.reason).toContain("signature");
  });

  it("blocks tool call with insufficient scope", async () => {
    const kp = await KeyPair.generate();
    const { api, hooks } = createMockAPI({
      trustKeys: [kp.publicKeyMultibase()],
    });
    aipGuard.register(api);

    const handler = hooks.get("before_tool_call")!;
    const token = await makeToken(kp, ["tool:search"]); // only has search
    const result = (await handler({
      toolName: "delete_all", // tries to call delete_all
      headers: { "X-AIP-Token": token },
    })) as HookResult;

    expect(result.block).toBe(true);
    expect(result.reason).toContain("scope");
  });

  it("blocks when no token and policy is block", async () => {
    const { api, hooks } = createMockAPI({
      trustKeys: ["z6MkSomeKey"],
      unsignedSkills: "block",
    });
    aipGuard.register(api);

    const handler = hooks.get("before_tool_call")!;
    const result = (await handler({
      toolName: "search",
      headers: {},
    })) as HookResult;

    expect(result.block).toBe(true);
    expect(result.reason).toContain("No AIP token");
  });

  it("warns but allows when no token and policy is warn", async () => {
    const { api, hooks } = createMockAPI({
      trustKeys: ["z6MkSomeKey"],
      unsignedSkills: "warn",
    });
    aipGuard.register(api);

    const handler = hooks.get("before_tool_call")!;
    const result = await handler({
      toolName: "search",
      headers: {},
    });

    // No result = allow (with warning logged to stderr)
    expect(result).toBeUndefined();
  });

  it("passes through when no trust keys configured", async () => {
    const { api, hooks } = createMockAPI({
      trustKeys: [],
    });
    aipGuard.register(api);

    const handler = hooks.get("before_tool_call")!;
    const result = await handler({
      toolName: "search",
      headers: { "X-AIP-Token": "some-token" },
    });

    expect(result).toBeUndefined();
  });

  it("extracts token from A2A metadata", async () => {
    const kp = await KeyPair.generate();
    const { api, hooks } = createMockAPI({
      trustKeys: [kp.publicKeyMultibase()],
    });
    aipGuard.register(api);

    const handler = hooks.get("before_tool_call")!;
    const token = await makeToken(kp, ["tool:search"]);
    const result = await handler({
      toolName: "search",
      metadata: { aip_token: token },
    });

    expect(result).toBeUndefined(); // allowed
  });
});
