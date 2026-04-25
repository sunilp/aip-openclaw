export interface AuditEntry {
  skill: string;
  tool: string;
  action: "allow" | "block" | "warn";
  reason?: string;
  author?: string;
  [key: string]: unknown;
}

export interface AuditLoggerOptions {
  writeFn?: (line: string) => void;
  filePath?: string;
}

export class AuditLogger {
  private readonly writeFn: (line: string) => void;

  constructor(options: AuditLoggerOptions = {}) {
    if (options.writeFn) {
      this.writeFn = options.writeFn;
    } else if (options.filePath) {
      const { appendFileSync } = require("node:fs");
      this.writeFn = (line) => appendFileSync(options.filePath!, line + "\n");
    } else {
      this.writeFn = () => {};
    }
  }

  log(entry: AuditEntry): void {
    const record = { ts: new Date().toISOString(), ...entry };
    this.writeFn(JSON.stringify(record));
  }
}
