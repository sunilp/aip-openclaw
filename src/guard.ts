import { AuditLogger } from "./audit-log.js";
import type { ManifestCapabilities } from "./manifest.js";

export interface GuardPolicy {
  unsignedSkills: "warn" | "block" | "allow";
  missingManifest: "warn" | "block" | "allow";
  expiredSignature: "block" | "warn";
  capabilityViolation: "block" | "warn";
}

export interface GuardDecision {
  allowed: boolean;
  reason?: string;
  warning?: string;
}

export interface GuardOptions {
  policy: GuardPolicy;
  auditLogger: AuditLogger;
}

interface ToolCallOptions {
  isShell?: boolean;
  isNetwork?: boolean;
  domain?: string;
  filePath?: string;
  isFileWrite?: boolean;
}

interface BudgetWindow {
  count: number;
  windowStart: number;
}

const ONE_HOUR_MS = 60 * 60 * 1000;

export class AipGuard {
  private readonly policy: GuardPolicy;
  private readonly auditLogger: AuditLogger;
  private readonly budgetWindows: Map<string, BudgetWindow> = new Map();

  constructor(options: GuardOptions) {
    this.policy = options.policy;
    this.auditLogger = options.auditLogger;
  }

  checkToolCall(
    skillName: string,
    tool: string,
    capabilities: ManifestCapabilities,
    options: ToolCallOptions = {}
  ): GuardDecision {
    // Check shell access
    if (options.isShell) {
      if (!capabilities.isShellAllowed()) {
        const reason = "shell access is disabled in manifest";
        const decision: GuardDecision = { allowed: false, reason };
        this.auditLogger.log({ skill: skillName, tool, action: "block", reason });
        return decision;
      }
    }

    // Check network access
    if (options.isNetwork && options.domain !== undefined) {
      if (!capabilities.isNetworkAllowed(options.domain)) {
        const reason = `network access to domain "${options.domain}" not allowed`;
        const decision: GuardDecision = { allowed: false, reason };
        this.auditLogger.log({ skill: skillName, tool, action: "block", reason });
        return decision;
      }
    }

    // Check file access
    if (options.filePath !== undefined) {
      const allowed = options.isFileWrite
        ? capabilities.isFileWriteAllowed(options.filePath)
        : capabilities.isFileReadAllowed(options.filePath);
      if (!allowed) {
        const accessType = options.isFileWrite ? "write" : "read";
        const reason = `filesystem ${accessType} access to "${options.filePath}" not allowed`;
        const decision: GuardDecision = { allowed: false, reason };
        this.auditLogger.log({ skill: skillName, tool, action: "block", reason });
        return decision;
      }
    }

    // Check tool allowlist (skip for shell tools already checked above)
    if (!capabilities.isToolAllowed(tool)) {
      const reason = `tool "${tool}" not in mcp_tools.allow`;
      const action = this.policy.capabilityViolation === "block" ? "block" : "warn";
      const decision: GuardDecision =
        action === "block"
          ? { allowed: false, reason }
          : { allowed: true, warning: reason };
      this.auditLogger.log({ skill: skillName, tool, action, reason });
      return decision;
    }

    // Check invocation budget
    const maxInvocations = capabilities.budget.maxInvocationsPerHour;
    if (isFinite(maxInvocations)) {
      const now = Date.now();
      const window = this.budgetWindows.get(skillName);

      if (!window || now - window.windowStart >= ONE_HOUR_MS) {
        // Start new window
        this.budgetWindows.set(skillName, { count: 1, windowStart: now });
      } else if (window.count >= maxInvocations) {
        const reason = `invocation limit of ${maxInvocations} per hour exceeded`;
        const decision: GuardDecision = { allowed: false, reason };
        this.auditLogger.log({ skill: skillName, tool, action: "block", reason });
        return decision;
      } else {
        window.count += 1;
      }
    }

    this.auditLogger.log({ skill: skillName, tool, action: "allow" });
    return { allowed: true };
  }

  checkUnsignedSkill(skillName: string): GuardDecision {
    const policy = this.policy.unsignedSkills;
    const tool = "__unsigned__";

    if (policy === "block") {
      const reason = "skill is unsigned";
      this.auditLogger.log({ skill: skillName, tool, action: "block", reason });
      return { allowed: false, reason };
    }

    if (policy === "warn") {
      const warning = `unsigned skill "${skillName}" — signature missing`;
      this.auditLogger.log({ skill: skillName, tool, action: "warn", reason: warning });
      return { allowed: true, warning };
    }

    // allow
    this.auditLogger.log({ skill: skillName, tool, action: "allow" });
    return { allowed: true };
  }

  checkMissingManifest(skillName: string): GuardDecision {
    const policy = this.policy.missingManifest;
    const tool = "__manifest__";

    if (policy === "block") {
      const reason = "manifest missing";
      this.auditLogger.log({ skill: skillName, tool, action: "block", reason });
      return { allowed: false, reason };
    }

    if (policy === "warn") {
      const warning = `skill "${skillName}" has no manifest`;
      this.auditLogger.log({ skill: skillName, tool, action: "warn", reason: warning });
      return { allowed: true, warning };
    }

    // allow
    this.auditLogger.log({ skill: skillName, tool, action: "allow" });
    return { allowed: true };
  }
}
