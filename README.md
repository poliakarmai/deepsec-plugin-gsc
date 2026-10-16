# @poliakarm/plugin-gsc

GSC (Git Security Checker) plugin for deepsec — deterministic matchers + PoC-backed finding verification.

## What it does

1. **Deterministic matchers** — 3 high-signal rules ported from GSC's Python detectors:
   - `gsc-llm-eval-injection` — eval()/new Function() on untrusted input
   - `gsc-llm-nosql-injection` — NoSQL operator injection ($where/$ne/...)
   - `gsc-llm-command-injection` — command injection via exec/system/subprocess

2. **PoC verifier** — `gsc-verify` notifier runs GSC on each finding to confirm it's real (not a false positive) and generates proof-of-concept.

## Installation

```bash
# via git (recommended for now)
npm install github:poliakarmai/deepsec-plugin-gsc

# or via npm (when published)
npm install @poliakarm/plugin-gsc
```

## Usage

```typescript
// deepsec.config.ts
import { defineConfig } from "deepsec/config";
import gscPlugin from "@poliakarm/plugin-gsc";

export default defineConfig({
  projects: [{ id: "my-app", root: "./my-app" }],
  plugins: [gscPlugin()],
});
```

### Options

```typescript
gscPlugin({
  gscPath: "/path/to/gsc-core",  // default: ~/gsc-core
  telemetry: false,               // future: opt-in telemetry
})
```

## How it works

### Matchers

Each matcher is a TypeScript port of a GSC Python detector. They use the same regex patterns but run natively in deepsec's scanner phase.

### Notifier

When deepsec finds a candidate, the `gsc-verify` notifier:
1. Runs `gsc_external.py scan <file>` on the finding's file
2. Parses the JSON output
3. Matches the finding by file path
4. Returns verification metadata (rule_id, severity, confidence_score)

If GSC confirms the finding, you get a verified vulnerability with deterministic proof.

## Why this exists

LLM-based scanners (like deepsec) are great at finding candidates but can produce false positives. GSC provides deterministic verification — the same finding, same proof, every time.

This plugin bridges the two: deepsec's breadth + GSC's precision.

## License

Apache-2.0
