# aip-openclaw

AIP security plugin for OpenClaw. Adds verifiable skill author identity, capability manifests, and runtime enforcement using the [Agent Identity Protocol](https://sunilprakash.com/aip/).

## Why

OpenClaw skills run with unrestricted access by default. This plugin adds:

- **Skill signing** -- Ed25519 signatures prove who wrote a skill and that it hasn't been tampered with
- **Capability manifests** -- Skills declare exactly what they need (MCP tools, network, files, shell)
- **Runtime enforcement** -- The guard blocks undeclared access and logs every decision
- **Progressive security** -- Works without any config (warns), tightens as you adopt

## Quick Start

```bash
npm install -g aip-openclaw

# Generate a manifest for your skill
aip-openclaw init ./my-skill/

# Review and tighten aip-manifest.toml, then sign
aip-openclaw sign ./my-skill/

# Verify a skill before running it
aip-openclaw verify ./my-skill/
```

## Progressive Security

| Level | Author does | User gets |
|-------|------------|-----------|
| 0 | Nothing | Skill works with warnings |
| 1 | `aip-openclaw init` | Capability enforcement |
| 2 | `aip-openclaw sign` | Identity verification + enforcement |
| 3 | Community attestation | Web-of-trust (future) |

## Programmatic API

```typescript
import { signSkill, verifySkill, AipGuard, parseManifest } from "aip-openclaw";
import { KeyPair } from "@aip-protocol/core";

// Sign a skill
const kp = await KeyPair.generate();
await signSkill("./my-skill", kp, "my-skill");

// Verify a skill
const result = await verifySkill("./my-skill");
console.log(result.valid); // true

// Runtime enforcement
const manifest = parseManifest(fs.readFileSync("aip-manifest.toml", "utf-8"));
const guard = new AipGuard({ policy, auditLogger });
const decision = guard.checkToolCall("my-skill", "search", manifest.capabilities);
```

## Protocol

- Paper: [arXiv:2603.24775](https://arxiv.org/abs/2603.24775)
- IETF: [draft-prakash-aip-00](https://datatracker.ietf.org/doc/draft-prakash-aip/)
- Spec: [sunilprakash.com/aip/](https://sunilprakash.com/aip/)
- TypeScript SDK: [github.com/sunilp/aip-node](https://github.com/sunilp/aip-node)

## License

Apache 2.0
