import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execSync } from "node:child_process";

const CLI_CWD = "/Users/sunilp/Development/sunil-ws/me/aip-openclaw";

describe("CLI", () => {
  let skillDir: string;

  beforeEach(() => {
    skillDir = mkdtempSync(join(tmpdir(), "aip-cli-test-"));
    writeFileSync(join(skillDir, "SKILL.md"), "# CLI Test Skill\nA test.");
    writeFileSync(join(skillDir, "main.ts"), "console.log('cli test');");
  });

  afterEach(() => {
    rmSync(skillDir, { recursive: true, force: true });
  });

  it("sign command creates .aip-signature", () => {
    const result = execSync(
      `npx tsx src/cli.ts sign ${skillDir} --skill-name cli-test`,
      { cwd: CLI_CWD, encoding: "utf-8" }
    );
    expect(existsSync(join(skillDir, ".aip-signature"))).toBe(true);
    expect(result).toContain("Signed");
  });

  it("verify command reports valid signature", () => {
    execSync(`npx tsx src/cli.ts sign ${skillDir} --skill-name cli-test`, { cwd: CLI_CWD });
    const result = execSync(
      `npx tsx src/cli.ts verify ${skillDir}`,
      { cwd: CLI_CWD, encoding: "utf-8" }
    );
    expect(result).toContain("valid");
  });

  it("verify command detects tampered file", () => {
    execSync(`npx tsx src/cli.ts sign ${skillDir} --skill-name cli-test`, { cwd: CLI_CWD });
    writeFileSync(join(skillDir, "main.ts"), "TAMPERED");
    try {
      execSync(`npx tsx src/cli.ts verify ${skillDir}`, { cwd: CLI_CWD, encoding: "utf-8" });
      expect.fail("Should have thrown");
    } catch (err: any) {
      const output = (err.stderr?.toString() || "") + (err.stdout?.toString() || "");
      expect(output).toContain("hash mismatch");
    }
  });

  it("init command generates aip-manifest.toml", () => {
    execSync(`npx tsx src/cli.ts init ${skillDir}`, { cwd: CLI_CWD });
    expect(existsSync(join(skillDir, "aip-manifest.toml"))).toBe(true);
    const content = readFileSync(join(skillDir, "aip-manifest.toml"), "utf-8");
    expect(content).toContain("[manifest]");
    expect(content).toContain("skill_name");
  });

  it("keygen creates a key file", () => {
    const keyFile = join(skillDir, "test.key");
    const result = execSync(
      `npx tsx src/cli.ts keygen --key-file ${keyFile}`,
      { cwd: CLI_CWD, encoding: "utf-8" }
    );
    expect(existsSync(keyFile)).toBe(true);
    expect(result).toContain("z"); // multibase public key
  });

  it("sign reuses existing key", () => {
    const keyFile = join(skillDir, "reuse.key");
    execSync(`npx tsx src/cli.ts keygen --key-file ${keyFile}`, { cwd: CLI_CWD });
    execSync(`npx tsx src/cli.ts sign ${skillDir} --skill-name reuse-test --key-file ${keyFile}`, { cwd: CLI_CWD });

    const sigContent = readFileSync(join(skillDir, ".aip-signature"), "utf-8");
    const authorMatch = sigContent.match(/author = "([^"]+)"/);

    // Sign again with same key
    rmSync(join(skillDir, ".aip-signature"));
    execSync(`npx tsx src/cli.ts sign ${skillDir} --skill-name reuse-test --key-file ${keyFile}`, { cwd: CLI_CWD });
    const sigContent2 = readFileSync(join(skillDir, ".aip-signature"), "utf-8");
    const authorMatch2 = sigContent2.match(/author = "([^"]+)"/);

    expect(authorMatch![1]).toBe(authorMatch2![1]); // Same author key
  });
});
