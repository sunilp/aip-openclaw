import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { rmSync } from "node:fs";
import { signSkill } from "../sign.js";
import { verifySkill, VerificationResult } from "../verify.js";
import { KeyPair } from "@aip-protocol/core";

describe("verifySkill", () => {
  let skillDir: string;
  let kp: KeyPair;

  beforeEach(async () => {
    skillDir = mkdtempSync(join(tmpdir(), "aip-verify-test-"));
    writeFileSync(join(skillDir, "SKILL.md"), "# Test Skill\nA test.");
    writeFileSync(join(skillDir, "main.ts"), "console.log('hello');");
    kp = await KeyPair.generate();
    await signSkill(skillDir, kp, "test-skill");
  });

  afterEach(() => {
    rmSync(skillDir, { recursive: true, force: true });
  });

  it("verifies a valid signed skill", async () => {
    const result = await verifySkill(skillDir, [kp.publicKeyMultibase()]);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.author).toBe(`aip:key:ed25519:${kp.publicKeyMultibase()}`);
    expect(result.fileCount).toBe(2);
  });

  it("detects tampered file", async () => {
    writeFileSync(join(skillDir, "main.ts"), "console.log('TAMPERED');");
    const result = await verifySkill(skillDir, [kp.publicKeyMultibase()]);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("hash mismatch"))).toBe(true);
  });

  it("detects extra unlisted file", async () => {
    writeFileSync(join(skillDir, "backdoor.ts"), "steal_data();");
    const result = await verifySkill(skillDir, [kp.publicKeyMultibase()]);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("unlisted"))).toBe(true);
  });

  it("detects missing file", async () => {
    unlinkSync(join(skillDir, "main.ts"));
    const result = await verifySkill(skillDir, [kp.publicKeyMultibase()]);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("missing"))).toBe(true);
  });

  it("rejects expired signature", async () => {
    const sigPath = join(skillDir, ".aip-signature");
    let content = readFileSync(sigPath, "utf-8");
    content = content.replace(/expires_at = "[^"]*"/, 'expires_at = "2020-01-01T00:00:00.000Z"');
    writeFileSync(sigPath, content);
    const result = await verifySkill(skillDir, [kp.publicKeyMultibase()]);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("expired"))).toBe(true);
  });

  it("rejects untrusted author", async () => {
    const otherKp = await KeyPair.generate();
    const result = await verifySkill(skillDir, [otherKp.publicKeyMultibase()]);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("not in trust list"))).toBe(true);
  });

  it("works without trust list (signature-only verification)", async () => {
    const result = await verifySkill(skillDir);
    expect(result.valid).toBe(true);
    expect(result.trusted).toBe(false);
  });

  it("reports missing .aip-signature", async () => {
    unlinkSync(join(skillDir, ".aip-signature"));
    const result = await verifySkill(skillDir);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("No .aip-signature"))).toBe(true);
  });
});
