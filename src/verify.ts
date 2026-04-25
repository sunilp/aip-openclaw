import { createHash } from "node:crypto";
import { readdirSync, readFileSync, lstatSync, existsSync } from "node:fs";
import { join, posix } from "node:path";
import { parse as parseToml } from "smol-toml";
import picomatch from "picomatch";
import { base58btc } from "multiformats/bases/base58";
import { KeyPair } from "@aip-sdk/core";

export interface VerificationResult {
  valid: boolean;
  trusted: boolean;
  author: string | null;
  signedAt: string | null;
  expiresAt: string | null;
  fileCount: number;
  errors: string[];
  warnings: string[];
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

/** Build a canonical TOML string for verification. Must match sign.ts exactly. */
function canonicalToml(
  envelopeFields: {
    aip_version: string;
    author: string;
    content_root: string;
    expires_at: string;
    file_count: number;
    schema_version: number;
    signed_at: string;
    skill_name: string;
  },
  files: Record<string, string>,
): string {
  const lines: string[] = [];

  lines.push("[envelope]");

  const fields: [string, string | number][] = [
    ["aip_version", envelopeFields.aip_version],
    ["author", envelopeFields.author],
    ["content_root", envelopeFields.content_root],
    ["expires_at", envelopeFields.expires_at],
    ["file_count", envelopeFields.file_count],
    ["schema_version", envelopeFields.schema_version],
    ["signed_at", envelopeFields.signed_at],
    ["skill_name", envelopeFields.skill_name],
  ];

  for (const [key, value] of fields) {
    if (typeof value === "number") {
      lines.push(`${key} = ${value}`);
    } else {
      lines.push(`${key} = ${JSON.stringify(value)}`);
    }
  }

  lines.push("");
  lines.push("[files]");

  const sortedFilePaths = Object.keys(files).sort();
  for (const filePath of sortedFilePaths) {
    lines.push(`${JSON.stringify(filePath)} = ${JSON.stringify(files[filePath])}`);
  }

  return lines.join("\n") + "\n";
}

/**
 * Verify a signed skill directory.
 * @param skillDir - Path to the skill directory
 * @param trustList - Optional list of trusted public key multibase strings
 */
export async function verifySkill(
  skillDir: string,
  trustList?: string[],
): Promise<VerificationResult> {
  const result: VerificationResult = {
    valid: false,
    trusted: false,
    author: null,
    signedAt: null,
    expiresAt: null,
    fileCount: 0,
    errors: [],
    warnings: [],
  };

  // 1. Read and parse .aip-signature
  const sigPath = join(skillDir, ".aip-signature");
  if (!existsSync(sigPath)) {
    result.errors.push("No .aip-signature file found");
    return result;
  }

  let parsed: Record<string, unknown>;
  try {
    const sigContent = readFileSync(sigPath, "utf-8");
    parsed = parseToml(sigContent) as Record<string, unknown>;
  } catch (err) {
    result.errors.push(`Failed to parse .aip-signature: ${err}`);
    return result;
  }

  // 2. Extract envelope and files sections
  const envelope = parsed["envelope"] as Record<string, unknown> | undefined;
  const filesSection = parsed["files"] as Record<string, unknown> | undefined;
  const envelopeSig = parsed["envelope_signature"] as Record<string, unknown> | undefined;

  if (!envelope || !filesSection || !envelopeSig) {
    result.errors.push("Invalid .aip-signature: missing required sections");
    return result;
  }

  const author = envelope["author"] as string | undefined;
  const signedAt = envelope["signed_at"] as string | undefined;
  const expiresAt = envelope["expires_at"] as string | undefined;
  const fileCount = envelope["file_count"] as number | undefined;
  const schemaVersion = envelope["schema_version"] as number | undefined;
  const skillName = envelope["skill_name"] as string | undefined;
  const aipVersion = envelope["aip_version"] as string | undefined;
  const contentRoot = envelope["content_root"] as string | undefined;
  const signature = envelopeSig["signature"] as string | undefined;

  if (!author || !signedAt || !expiresAt || fileCount === undefined || !signature) {
    result.errors.push("Invalid .aip-signature: missing required envelope fields");
    return result;
  }

  result.author = author;
  result.signedAt = signedAt;
  result.expiresAt = expiresAt;
  result.fileCount = fileCount;

  // 3. Check expiry
  const now = new Date();
  const expiry = new Date(expiresAt);
  if (expiry < now) {
    result.errors.push(`Signature expired at ${expiresAt}`);
    return result;
  }

  // 4. Check trust list (if provided)
  if (trustList && trustList.length > 0) {
    // Extract multibase key from author: "aip:key:ed25519:<multibase>"
    const match = author.match(/^aip:key:ed25519:(.+)$/);
    if (!match) {
      result.errors.push(`Invalid author format: ${author}`);
      return result;
    }
    const authorKey = match[1];
    if (!trustList.includes(authorKey)) {
      result.errors.push(`Author key ${authorKey} is not in trust list`);
      return result;
    }
    result.trusted = true;
  }

  // 5. Collect actual files in the directory (same logic as signing)
  const ignorePatterns = loadIgnorePatterns(skillDir);
  let isMatch: ((path: string) => boolean) | null = null;
  if (ignorePatterns.length > 0) {
    const matcher = picomatch(ignorePatterns, { dot: true });
    isMatch = matcher;
  }

  const actualFiles = collectFiles(skillDir, skillDir, isMatch);
  const listedFiles = filesSection as Record<string, string>;

  // 6. Check for extra unlisted files
  for (const actualPath of actualFiles.keys()) {
    if (!(actualPath in listedFiles)) {
      result.errors.push(`unlisted file found: ${actualPath}`);
    }
  }

  // 7. Check for missing files and hash mismatches
  for (const [listedPath, expectedHash] of Object.entries(listedFiles)) {
    const actualContent = actualFiles.get(listedPath);
    if (actualContent === undefined) {
      result.errors.push(`Listed file is missing: ${listedPath}`);
      continue;
    }
    // Compute hash using same method as sign.ts
    const hash = createHash("sha256");
    hash.update(listedPath);
    hash.update(actualContent);
    const actualHash = `sha256:${hash.digest("hex")}`;
    if (actualHash !== expectedHash) {
      result.errors.push(`File hash mismatch for ${listedPath}: expected ${expectedHash}, got ${actualHash}`);
    }
  }

  // If file errors exist, return now (before sig verification)
  if (result.errors.length > 0) {
    return result;
  }

  // 8. Verify Ed25519 signature
  // Rebuild canonical TOML from envelope + files (same format as signing)
  const envelopeForToml = {
    aip_version: aipVersion as string,
    author: author,
    content_root: contentRoot as string,
    expires_at: expiresAt,
    file_count: fileCount,
    schema_version: schemaVersion as number,
    signed_at: signedAt,
    skill_name: skillName as string,
  };

  const tomlStr = canonicalToml(envelopeForToml, listedFiles);
  const tomlHash = createHash("sha256").update(tomlStr).digest();

  // Decode signature from base58btc
  const sigBytes = base58btc.decode(signature);

  // Get public key bytes from author
  const keyMatch = author.match(/^aip:key:ed25519:(.+)$/);
  if (!keyMatch) {
    result.errors.push(`Cannot extract public key from author: ${author}`);
    return result;
  }
  const pubKeyMultibase = keyMatch[1];
  const pubKeyBytes = KeyPair.decodeMultibase(pubKeyMultibase);

  const valid = await KeyPair.verify(pubKeyBytes, tomlHash, sigBytes);
  if (!valid) {
    result.errors.push("Signature verification failed");
    return result;
  }

  result.valid = true;
  return result;
}
