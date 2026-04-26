# @aip-sdk/openclaw-plugin

Native OpenClaw plugin that hooks into `before_tool_call` to verify AIP delegation tokens and enforce capability policies on every tool execution.

## Install

```bash
openclaw plugins install clawhub:@aip-sdk/openclaw-plugin
```

Or via npm:

```bash
npm install @aip-sdk/openclaw-plugin
```

## Configure

In your OpenClaw config:

```json
{
  "plugins": {
    "enabled": ["aip-guard"],
    "entries": {
      "aip-guard": {
        "config": {
          "trustKeys": ["z6MkYourEd25519PublicKey..."],
          "unsignedSkills": "warn",
          "auditLog": "./aip-audit.jsonl"
        }
      }
    }
  }
}
```

## What it does

Every tool call passes through AIP Guard before execution:

1. **Extract** the AIP token from `X-AIP-Token` header or A2A metadata
2. **Verify** the Ed25519 signature against configured trust keys
3. **Check scope** against the token's capability list
4. **Allow or block** with a JSONL audit log entry

## Policy modes

| `unsignedSkills` | No token present | Effect |
|-----------------|-----------------|--------|
| `"allow"` | Pass through silently | No enforcement |
| `"warn"` (default) | Log warning, allow | Visibility without disruption |
| `"block"` | Block tool call | Full enforcement |

## Audit log

Every decision is logged as JSONL:

```json
{"ts":"2026-04-26T02:19:28Z","decision":"deny","tool":"delete_all","subject":"aip:key:ed25519:z...","reason":"scope_insufficient: tool:delete_all not in token scope [tool:search]"}
```
