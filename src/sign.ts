import { createHash } from "node:crypto";
import { readdirSync, readFileSync, lstatSync, existsSync } from "node:fs";
import { writeFileSync } from "node:fs";
import { join, posix } from "node:path";
import picomatch from "picomatch";
import { base58btc } from "multiformats/bases/base58";
import { KeyPair } from "@aip-protocol/core";

export interface SignatureEnvelope {
  schemaVersion: number;
  skillName: string;
  contentRoot: string;
  fileCount: number;
  author: string;
  signedAt: string;
  aipVersion: string;
  expiresAt: string;
  files: Record<string, string>;
  signature: string;
}

/** Normalize a path to use forward slashes */
function normalizePath(p: string): string {
  return p.replace(/\\/g, "/");
}

/** Load .aipignore patterns from the skill directory, if present */
function loadIgnorePatterns(skillDir: string): string[] {
  const ignorePath = join(skillDir, ".aipignore");
  if (!existsSync(ignorePath)) return [];
  const content = readFileSync(ignorePath, "utf-8");
  return content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"));
}

/** Walk directory tree, returning relPath -> Buffer for each file. Skips symlinks and ignored paths. */
function collectFiles(
  dir: string,
  baseDir: string,
  isMatch: ((path: string) => boolean) | null,
): Map<string, Buffer> {
  const results = new Map<string, Buffer>();

  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    // Skip special files always
    if (entry.name === ".aip-signature") continue;
    if (entry.name === ".aipignore") continue;
    if (entry.name === ".git") continue;

    const fullPath = join(dir, entry.name);
    const relPath = normalizePath(posix.normalize(fullPath.slice(baseDir.length + 1)));

    // Skip symlinks
    const stat = lstatSync(fullPath);
    if (stat.isSymbolicLink()) continue;

    if (stat.isDirectory()) {
      // Check if directory itself is ignored (e.g., __pycache__/)
      const dirRelPath = relPath + "/";
      if (isMatch && (isMatch(relPath) || isMatch(dirRelPath))) continue;

      // Recurse
      const sub = collectFiles(fullPath, baseDir, isMatch);
      for (const [k, v] of sub) {
        results.set(k, v);
      }
    } else if (stat.isFile()) {
      // Check if file is ignored
      if (isMatch && isMatch(relPath)) continue;

      results.set(relPath, readFileSync(fullPath));
    }
  }

  return results;
}

/** SHA-256 hash of relPath + content, returns "sha256:hex" */
function hashFile(relPath: string, content: Buffer): string {
  const hash = createHash("sha256");
  hash.update(relPath);
  hash.update(content);
  return `sha256:${hash.digest("hex")}`;
}

/** Compute merkle root: sort keys by byte order, SHA-256 of concatenated hashes */
function computeMerkleRoot(fileHashes: Map<string, string>): string {
  const sortedKeys = Array.from(fileHashes.keys()).sort();
  const hash = createHash("sha256");
  for (const key of sortedKeys) {
    hash.update(fileHashes.get(key)!);
  }
  return `sha256:${hash.digest("hex")}`;
}

/** Build a canonical TOML string for signing. Sorted keys, deterministic output. */
function canonicalToml(
  envelope: Omit<SignatureEnvelope, "signature">,
): string {
  const lines: string[] = [];

  lines.push("[envelope]");

  // Sorted keys for envelope section (snake_case)
  const envelopeFields: [string, string | number][] = [
    ["aip_version", envelope.aipVersion],
    ["author", envelope.author],
    ["content_root", envelope.contentRoot],
    ["expires_at", envelope.expiresAt],
    ["file_count", envelope.fileCount],
    ["schema_version", envelope.schemaVersion],
    ["signed_at", envelope.signedAt],
    ["skill_name", envelope.skillName],
  ];

  for (const [key, value] of envelopeFields) {
    if (typeof value === "number") {
      lines.push(`${key} = ${value}`);
    } else {
      lines.push(`${key} = ${JSON.stringify(value)}`);
    }
  }

  lines.push("");
  lines.push("[files]");

  // Sorted file paths
  const sortedFilePaths = Object.keys(envelope.files).sort();
  for (const filePath of sortedFilePaths) {
    lines.push(`${JSON.stringify(filePath)} = ${JSON.stringify(envelope.files[filePath])}`);
  }

  return lines.join("\n") + "\n";
}

/**
 * Sign a skill directory and write a .aip-signature file.
 * Returns the SignatureEnvelope.
 */
export async function signSkill(
  skillDir: string,
  keypair: KeyPair,
  skillName: string,
  expiryDays: number = 365,
): Promise<SignatureEnvelope> {
  // Load ignore patterns
  const ignorePatterns = loadIgnorePatterns(skillDir);
  let isMatch: ((path: string) => boolean) | null = null;
  if (ignorePatterns.length > 0) {
    const matcher = picomatch(ignorePatterns, { dot: true });
    isMatch = matcher;
  }

  // Collect all files
  const fileMap = collectFiles(skillDir, skillDir, isMatch);

  // Hash each file
  const fileHashes = new Map<string, string>();
  const filesRecord: Record<string, string> = {};
  for (const [relPath, content] of fileMap) {
    const hash = hashFile(relPath, content);
    fileHashes.set(relPath, hash);
    filesRecord[relPath] = hash;
  }

  // Compute merkle root
  const contentRoot = computeMerkleRoot(fileHashes);

  // Build envelope (without signature)
  const now = new Date();
  const expiresAt = new Date(now.getTime() + expiryDays * 86400000);
  const author = `aip:key:ed25519:${keypair.publicKeyMultibase()}`;

  const envelopeWithoutSig: Omit<SignatureEnvelope, "signature"> = {
    schemaVersion: 1,
    skillName,
    contentRoot,
    fileCount: fileMap.size,
    author,
    signedAt: now.toISOString(),
    aipVersion: "0.2.0",
    expiresAt: expiresAt.toISOString(),
    files: filesRecord,
  };

  // Canonical TOML for signing
  const tomlStr = canonicalToml(envelopeWithoutSig);

  // Sign SHA-256 of canonical TOML
  const tomlHash = createHash("sha256").update(tomlStr).digest();
  const sigBytes = await keypair.sign(tomlHash);
  const signature = base58btc.encode(sigBytes);

  // Full envelope
  const envelope: SignatureEnvelope = {
    ...envelopeWithoutSig,
    signature,
  };

  // Write .aip-signature file (TOML format with signature appended)
  const sigToml = tomlStr + `\n[envelope_signature]\nsignature = ${JSON.stringify(signature)}\n`;
  writeFileSync(join(skillDir, ".aip-signature"), sigToml, "utf-8");

  return envelope;
}
