import { parse as parseToml } from "smol-toml";
import picomatch from "picomatch";

export interface SkillManifest {
  schemaVersion: number;
  skillName: string;
  capabilities: ManifestCapabilities;
}

export class ManifestCapabilities {
  readonly mcpTools: { allow: string[] };
  readonly network: { allow: string[] | "none" };
  readonly filesystem: { read: string[] | "none"; write: string[] | "none" };
  readonly shell: { enabled: boolean };
  readonly budget: { maxUsdPerInvocation: number; maxInvocationsPerHour: number };
  readonly delegation: { enabled: boolean; maxDepth: number };

  constructor(caps: {
    mcpTools?: { allow?: string[] };
    network?: { allow?: string[] | "none" };
    filesystem?: { read?: string[] | "none"; write?: string[] | "none" };
    shell?: { enabled?: boolean };
    budget?: { maxUsdPerInvocation?: number; maxInvocationsPerHour?: number };
    delegation?: { enabled?: boolean; maxDepth?: number };
  }) {
    this.mcpTools = { allow: caps.mcpTools?.allow ?? ["*"] };
    this.network = { allow: caps.network?.allow ?? ["*"] };
    this.filesystem = {
      read: caps.filesystem?.read ?? ["*"],
      write: caps.filesystem?.write ?? ["*"],
    };
    this.shell = { enabled: caps.shell?.enabled ?? true };
    this.budget = {
      maxUsdPerInvocation: caps.budget?.maxUsdPerInvocation ?? Infinity,
      maxInvocationsPerHour: caps.budget?.maxInvocationsPerHour ?? Infinity,
    };
    this.delegation = {
      enabled: caps.delegation?.enabled ?? true,
      maxDepth: caps.delegation?.maxDepth ?? 10,
    };
  }

  isToolAllowed(tool: string): boolean {
    if (this.mcpTools.allow.includes("*")) return true;
    return this.mcpTools.allow.includes(tool);
  }

  isNetworkAllowed(domain: string): boolean {
    const allow = this.network.allow;
    if (allow === "none") return false;
    if (allow.includes("*")) return true;
    return allow.includes(domain);
  }

  isFileReadAllowed(path: string): boolean {
    const read = this.filesystem.read;
    if (read === "none") return false;
    if (read.includes("*")) return true;
    return read.some((pattern) => picomatch.isMatch(path, pattern));
  }

  isFileWriteAllowed(path: string): boolean {
    const write = this.filesystem.write;
    if (write === "none") return false;
    if (write.includes("*")) return true;
    return write.some((pattern) => picomatch.isMatch(path, pattern));
  }

  isShellAllowed(): boolean {
    return this.shell.enabled;
  }
}

export function parseManifest(tomlStr: string): SkillManifest {
  const data = parseToml(tomlStr) as Record<string, any>;

  if (!data.manifest) {
    throw new Error("Missing [manifest] section in aip-manifest.toml");
  }
  if (!data.manifest.skill_name) {
    throw new Error("Missing skill_name in [manifest] section");
  }

  const caps = data.capabilities ?? {};

  return {
    schemaVersion: data.manifest.schema_version ?? 1,
    skillName: data.manifest.skill_name,
    capabilities: new ManifestCapabilities({
      mcpTools: caps.mcp_tools ? { allow: caps.mcp_tools.allow } : undefined,
      network: caps.network ? { allow: caps.network.allow } : undefined,
      filesystem: caps.filesystem
        ? { read: caps.filesystem.read, write: caps.filesystem.write }
        : undefined,
      shell: caps.shell ? { enabled: caps.shell.enabled } : undefined,
      budget: caps.budget
        ? {
            maxUsdPerInvocation: caps.budget.max_usd_per_invocation,
            maxInvocationsPerHour: caps.budget.max_invocations_per_hour,
          }
        : undefined,
      delegation: caps.delegation
        ? { enabled: caps.delegation.enabled, maxDepth: caps.delegation.max_depth }
        : undefined,
    }),
  };
}
