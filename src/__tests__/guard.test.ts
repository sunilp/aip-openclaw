import { describe, it, expect, beforeEach } from "vitest";
import { AipGuard, GuardDecision } from "../guard.js";
import { AuditLogger } from "../audit-log.js";
import { ManifestCapabilities } from "../manifest.js";

describe("AuditLogger", () => {
  it("logs entries as JSON lines", () => {
    const entries: string[] = [];
    const logger = new AuditLogger({ writeFn: (line) => entries.push(line) });
    logger.log({ skill: "test", tool: "search", action: "allow" });
    expect(entries).toHaveLength(1);
    const parsed = JSON.parse(entries[0]);
    expect(parsed.skill).toBe("test");
    expect(parsed.tool).toBe("search");
    expect(parsed.action).toBe("allow");
    expect(parsed.ts).toBeDefined();
  });
});

describe("AipGuard", () => {
  let guard: AipGuard;
  let logEntries: string[];

  beforeEach(() => {
    logEntries = [];
    guard = new AipGuard({
      policy: {
        unsignedSkills: "warn",
        missingManifest: "warn",
        expiredSignature: "block",
        capabilityViolation: "block",
      },
      auditLogger: new AuditLogger({ writeFn: (line) => logEntries.push(line) }),
    });
  });

  it("allows tool call within manifest scope", () => {
    const caps = new ManifestCapabilities({ mcpTools: { allow: ["search", "read"] } });
    const decision = guard.checkToolCall("my-skill", "search", caps);
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBeUndefined();
  });

  it("blocks tool call outside manifest scope", () => {
    const caps = new ManifestCapabilities({ mcpTools: { allow: ["search"] } });
    const decision = guard.checkToolCall("my-skill", "delete", caps);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("not in mcp_tools.allow");
  });

  it("blocks shell when disabled in manifest", () => {
    const caps = new ManifestCapabilities({ mcpTools: { allow: ["*"] }, shell: { enabled: false } });
    const decision = guard.checkToolCall("my-skill", "run_shell", caps, { isShell: true });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("shell");
  });

  it("warns for unsigned skills when policy is warn", () => {
    const decision = guard.checkUnsignedSkill("unsigned-skill");
    expect(decision.allowed).toBe(true);
    expect(decision.warning).toContain("unsigned");
  });

  it("blocks unsigned skills when policy is block", () => {
    guard = new AipGuard({
      policy: { unsignedSkills: "block", missingManifest: "block", expiredSignature: "block", capabilityViolation: "block" },
      auditLogger: new AuditLogger({ writeFn: (line) => logEntries.push(line) }),
    });
    const decision = guard.checkUnsignedSkill("unsigned-skill");
    expect(decision.allowed).toBe(false);
  });

  it("logs all decisions to audit logger", () => {
    const caps = new ManifestCapabilities({ mcpTools: { allow: ["search"] } });
    guard.checkToolCall("my-skill", "search", caps);
    guard.checkToolCall("my-skill", "delete", caps);
    expect(logEntries).toHaveLength(2);
  });

  it("tracks budget per session", () => {
    const caps = new ManifestCapabilities({
      mcpTools: { allow: ["*"] },
      budget: { maxUsdPerInvocation: 1.0, maxInvocationsPerHour: 3 },
    });
    guard.checkToolCall("my-skill", "tool1", caps);
    guard.checkToolCall("my-skill", "tool2", caps);
    guard.checkToolCall("my-skill", "tool3", caps);
    const decision = guard.checkToolCall("my-skill", "tool4", caps);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("invocation limit");
  });
});
