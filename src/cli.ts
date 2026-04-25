#!/usr/bin/env node
import { Command } from "commander";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, basename } from "node:path";
import { KeyPair } from "@aip-protocol/core";
import { signSkill } from "./sign.js";
import { verifySkill } from "./verify.js";

const program = new Command();

program
  .name("aip-openclaw")
  .description("AIP security plugin for OpenClaw")
  .version("0.1.0");

program
  .command("sign <skill-dir>")
  .description("Sign a skill directory with an AIP identity")
  .option("--skill-name <name>", "Skill name (defaults to directory name)")
  .option("--expiry-days <days>", "Signature expiry in days", "365")
  .action(async (skillDir: string, opts) => {
    const skillName = opts.skillName ?? basename(skillDir);
    const expiryDays = parseInt(opts.expiryDays, 10);
    const kp = await KeyPair.generate();
    const envelope = await signSkill(skillDir, kp, skillName, expiryDays);
    console.log(`Signed "${skillName}" successfully.`);
    console.log(`  Author: ${envelope.author}`);
    console.log(`  Files: ${envelope.fileCount}`);
    console.log(`  Expires: ${envelope.expiresAt}`);
    console.log(`  Signature: ${join(skillDir, ".aip-signature")}`);
  });

program
  .command("verify <skill-dir>")
  .description("Verify a signed skill directory")
  .option("--trust <keys...>", "Trusted author public keys (multibase)")
  .action(async (skillDir: string, opts) => {
    const result = await verifySkill(skillDir, opts.trust);
    if (result.valid) {
      console.log("Signature valid");
      console.log(`  Author: ${result.author}`);
      console.log(`  Signed: ${result.signedAt}`);
      console.log(`  Expires: ${result.expiresAt}`);
      console.log(`  Files: ${result.fileCount}/${result.fileCount} verified`);
      console.log(`  Trust: ${result.trusted ? "author in trust list" : "no trust list provided"}`);
    } else {
      console.error("Verification failed");
      for (const err of result.errors) {
        console.error(`  - ${err}`);
      }
      process.exit(1);
    }
  });

program
  .command("init <skill-dir>")
  .description("Generate a draft aip-manifest.toml for a skill")
  .action(async (skillDir: string) => {
    const skillMdPath = join(skillDir, "SKILL.md");
    let skillName = basename(skillDir);
    if (existsSync(skillMdPath)) {
      const content = readFileSync(skillMdPath, "utf-8");
      const titleMatch = content.match(/^#\s+(.+)/m);
      if (titleMatch) {
        skillName = titleMatch[1].trim().toLowerCase().replace(/\s+/g, "-");
      }
    }
    const manifest = `[manifest]\nschema_version = 1\nskill_name = "${skillName}"\n\n[capabilities.mcp_tools]\nallow = ["*"]\n\n[capabilities.network]\nallow = ["*"]\n\n[capabilities.filesystem]\nread = ["*"]\nwrite = "none"\n\n[capabilities.shell]\nenabled = false\n\n[capabilities.budget]\nmax_usd_per_invocation = 1.00\nmax_invocations_per_hour = 100\n\n[capabilities.delegation]\nenabled = false\nmax_depth = 0\n`;
    const manifestPath = join(skillDir, "aip-manifest.toml");
    writeFileSync(manifestPath, manifest);
    console.log(`Generated ${manifestPath}`);
    console.log("Review and tighten the capabilities before signing.");
  });

program
  .command("guard")
  .description("Start the runtime guard proxy")
  .option("--port <port>", "Guard proxy port", "8090")
  .option("--upstream <url>", "Upstream MCP server URL", "http://localhost:8080")
  .action(async (opts) => {
    console.log(`AIP Guard starting on port ${opts.port} -> ${opts.upstream}`);
    console.log("Guard proxy not yet implemented in this version.");
  });

program.parse();
