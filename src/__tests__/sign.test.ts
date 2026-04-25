import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { rmSync } from "node:fs";
import { signSkill, SignatureEnvelope } from "../sign.js";
import { KeyPair } from "@aip-protocol/core";

describe("signSkill", () => {
  let skillDir: string;

  beforeEach(() => {
    skillDir = mkdtempSync(join(tmpdir(), "aip-sign-test-"));
    writeFileSync(join(skillDir, "SKILL.md"), "# Test Skill\nA test skill.");
    writeFileSync(join(skillDir, "main.ts"), "console.log('hello');");
  });

  afterEach(() => {
    rmSync(skillDir, { recursive: true, force: true });
  });

  it("signs a skill directory and creates .aip-signature", async () => {
    const kp = await KeyPair.generate();
    await signSkill(skillDir, kp, "test-skill");
    const sigPath = join(skillDir, ".aip-signature");
    const content = readFileSync(sigPath, "utf-8");
    expect(content).toContain("[envelope]");
    expect(content).toContain('skill_name = "test-skill"');
    expect(content).toContain("content_root");
    expect(content).toContain("signature");
  });

  it("includes all files in the envelope", async () => {
    const kp = await KeyPair.generate();
    const envelope = await signSkill(skillDir, kp, "test-skill");
    expect(envelope.fileCount).toBe(2);
    expect(envelope.files["SKILL.md"]).toBeDefined();
    expect(envelope.files["main.ts"]).toBeDefined();
  });

  it("sets correct author identity", async () => {
    const kp = await KeyPair.generate();
    const envelope = await signSkill(skillDir, kp, "test-skill");
    expect(envelope.author).toBe(`aip:key:ed25519:${kp.publicKeyMultibase()}`);
  });

  it("sets expiry one year from now", async () => {
    const kp = await KeyPair.generate();
    const envelope = await signSkill(skillDir, kp, "test-skill");
    const expires = new Date(envelope.expiresAt);
    const oneYearFromNow = new Date(Date.now() + 365 * 86400000);
    expect(Math.abs(expires.getTime() - oneYearFromNow.getTime())).toBeLessThan(60000);
  });

  it("ignores .aipignore patterns", async () => {
    writeFileSync(join(skillDir, ".aipignore"), "*.log\n__pycache__/\n");
    writeFileSync(join(skillDir, "debug.log"), "log data");
    mkdirSync(join(skillDir, "__pycache__"));
    writeFileSync(join(skillDir, "__pycache__", "cache.pyc"), "cache");
    const kp = await KeyPair.generate();
    const envelope = await signSkill(skillDir, kp, "test-skill");
    expect(envelope.files["debug.log"]).toBeUndefined();
    expect(envelope.files["__pycache__/cache.pyc"]).toBeUndefined();
    expect(envelope.fileCount).toBe(2);
  });

  it("does not follow symlinks", async () => {
    const targetDir = mkdtempSync(join(tmpdir(), "aip-symlink-target-"));
    writeFileSync(join(targetDir, "secret.txt"), "secret");
    symlinkSync(targetDir, join(skillDir, "linked"), "dir");
    const kp = await KeyPair.generate();
    const envelope = await signSkill(skillDir, kp, "test-skill");
    expect(envelope.files["linked/secret.txt"]).toBeUndefined();
    rmSync(targetDir, { recursive: true, force: true });
  });

  it("produces deterministic content root for same content", async () => {
    const seed = new Uint8Array(32).fill(99);
    const kp = await KeyPair.fromSeed(seed);
    const env1 = await signSkill(skillDir, kp, "test-skill");
    const env2 = await signSkill(skillDir, kp, "test-skill");
    expect(env1.contentRoot).toBe(env2.contentRoot);
  });
});
