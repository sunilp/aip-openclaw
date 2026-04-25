import { describe, it, expect } from "vitest";
import { parseManifest, ManifestCapabilities } from "../manifest.js";

const VALID_TOML = `
[manifest]
schema_version = 1
skill_name = "email-summarizer"

[capabilities.mcp_tools]
allow = ["read_email", "list_emails"]

[capabilities.network]
allow = ["imap.gmail.com", "smtp.gmail.com"]

[capabilities.filesystem]
read = ["/tmp/email-cache/*"]
write = "none"

[capabilities.shell]
enabled = false

[capabilities.budget]
max_usd_per_invocation = 0.50
max_invocations_per_hour = 100

[capabilities.delegation]
enabled = false
max_depth = 0
`;

describe("parseManifest", () => {
  it("parses a valid manifest", () => {
    const manifest = parseManifest(VALID_TOML);
    expect(manifest.schemaVersion).toBe(1);
    expect(manifest.skillName).toBe("email-summarizer");
    expect(manifest.capabilities.mcpTools.allow).toEqual(["read_email", "list_emails"]);
    expect(manifest.capabilities.network.allow).toEqual(["imap.gmail.com", "smtp.gmail.com"]);
    expect(manifest.capabilities.filesystem.read).toEqual(["/tmp/email-cache/*"]);
    expect(manifest.capabilities.filesystem.write).toBe("none");
    expect(manifest.capabilities.shell.enabled).toBe(false);
    expect(manifest.capabilities.budget.maxUsdPerInvocation).toBe(0.50);
    expect(manifest.capabilities.budget.maxInvocationsPerHour).toBe(100);
    expect(manifest.capabilities.delegation.enabled).toBe(false);
    expect(manifest.capabilities.delegation.maxDepth).toBe(0);
  });

  it("throws for missing manifest section", () => {
    expect(() => parseManifest("[capabilities]\n")).toThrow();
  });

  it("throws for missing skill_name", () => {
    expect(() => parseManifest("[manifest]\nschema_version = 1\n")).toThrow();
  });

  it("defaults missing capabilities to permissive", () => {
    const manifest = parseManifest(`
[manifest]
schema_version = 1
skill_name = "minimal"
`);
    expect(manifest.capabilities.mcpTools.allow).toEqual(["*"]);
    expect(manifest.capabilities.shell.enabled).toBe(true);
    expect(manifest.capabilities.delegation.enabled).toBe(true);
  });
});

describe("ManifestCapabilities", () => {
  it("isToolAllowed checks allowlist", () => {
    const manifest = parseManifest(VALID_TOML);
    expect(manifest.capabilities.isToolAllowed("read_email")).toBe(true);
    expect(manifest.capabilities.isToolAllowed("delete_email")).toBe(false);
  });

  it("isToolAllowed allows everything with wildcard", () => {
    const manifest = parseManifest(`
[manifest]
schema_version = 1
skill_name = "permissive"

[capabilities.mcp_tools]
allow = ["*"]
`);
    expect(manifest.capabilities.isToolAllowed("anything")).toBe(true);
  });

  it("isNetworkAllowed checks domain allowlist", () => {
    const manifest = parseManifest(VALID_TOML);
    expect(manifest.capabilities.isNetworkAllowed("imap.gmail.com")).toBe(true);
    expect(manifest.capabilities.isNetworkAllowed("evil.com")).toBe(false);
  });

  it("isFileReadAllowed checks glob patterns", () => {
    const manifest = parseManifest(VALID_TOML);
    expect(manifest.capabilities.isFileReadAllowed("/tmp/email-cache/msg1.txt")).toBe(true);
    expect(manifest.capabilities.isFileReadAllowed("/etc/passwd")).toBe(false);
  });

  it("isFileWriteAllowed blocks when write is none", () => {
    const manifest = parseManifest(VALID_TOML);
    expect(manifest.capabilities.isFileWriteAllowed("/tmp/anything")).toBe(false);
  });

  it("isShellAllowed returns enabled flag", () => {
    const manifest = parseManifest(VALID_TOML);
    expect(manifest.capabilities.isShellAllowed()).toBe(false);
  });
});
