export const VERSION = "0.1.0";

export { signSkill } from "./sign.js";
export type { SignatureEnvelope } from "./sign.js";
export { verifySkill } from "./verify.js";
export type { VerificationResult } from "./verify.js";
export { parseManifest, ManifestCapabilities } from "./manifest.js";
export type { SkillManifest } from "./manifest.js";
export { AipGuard } from "./guard.js";
export type { GuardPolicy, GuardDecision, GuardOptions } from "./guard.js";
export { AuditLogger } from "./audit-log.js";
export type { AuditEntry, AuditLoggerOptions } from "./audit-log.js";
