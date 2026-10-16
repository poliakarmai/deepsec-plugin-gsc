import { spawn } from "node:child_process";
import { resolve, relative, isAbsolute } from "node:path";
import type { NotifierPlugin, FindingNotification } from "./deepsec-types.js";
import type { GscPluginOptions } from "./index.js";

interface GscFinding {
  rule_id: string;
  severity: string;
  confidence_score: number;
  file: string;
  line?: number;
}

interface GscScanResult {
  findings: GscFinding[];
}

export function gscVerifyNotifier(opts?: GscPluginOptions): NotifierPlugin {
  const gscPath = opts?.gscPath ?? resolve(process.env.HOME ?? "~", "gsc-core");

  return {
    name: "gsc-verify",
    async notify(params: { finding: unknown; record: { filePath: string }; projectId: string }): Promise<FindingNotification> {
      const { record } = params;
      const filePath = record.filePath;

      // Trust boundary: reject path traversal
      if (filePath.includes("..")) {
        return {
          notifierName: "gsc-verify",
          notifiedAt: new Date().toISOString(),
          externalId: "path-traversal-rejected",
          extra: { verdict: "gsc-error", error: "path traversal rejected" },
        };
      }

      const absPath = isAbsolute(filePath) ? filePath : resolve(process.cwd(), filePath);

      try {
        // ponytail: sync subprocess, single file. Batch when needed.
        const result = await runGscScan(absPath, gscPath);
        
        if (!result || !result.findings || result.findings.length === 0) {
          return {
            notifierName: "gsc-verify",
            notifiedAt: new Date().toISOString(),
            externalId: "no-match",
            extra: { verdict: "no-match" },
          };
        }

        // Find matching finding by file
        const match = result.findings.find((f: GscFinding) => f.file === filePath);
        
        if (match) {
          return {
            notifierName: "gsc-verify",
            notifiedAt: new Date().toISOString(),
            externalId: match.rule_id,
            extra: {
              verdict: "verified",
              rule_id: match.rule_id,
              severity: match.severity,
              confidence_score: match.confidence_score,
            },
          };
        }

        return {
          notifierName: "gsc-verify",
          notifiedAt: new Date().toISOString(),
          externalId: "no-match",
          extra: { verdict: "no-match", findings_count: result.findings.length },
        };
      } catch (error) {
        return {
          notifierName: "gsc-verify",
          notifiedAt: new Date().toISOString(),
          externalId: "gsc-error",
          extra: { verdict: "gsc-error", error: String(error) },
        };
      }
    },
  };
}

function runGscScan(filePath: string, gscPath: string): Promise<GscScanResult | null> {
  return new Promise((resolve, reject) => {
    const proc = spawn(
      "python3",
      ["gsc_external.py", "scan", filePath, "--format", "json", "--output", "-"],
      { cwd: gscPath, timeout: 120000 }
    );

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data: Buffer) => { stdout += data; });
    proc.stderr.on("data", (data: Buffer) => { stderr += data; });

    proc.on("error", (err: Error) => reject(err));
    proc.on("close", (code: number | null) => {
      if (code !== 0) {
        reject(new Error(`GSC exited with code ${code}: ${stderr}`));
        return;
      }
      try {
        const result = JSON.parse(stdout) as GscScanResult;
        resolve(result);
      } catch (err) {
        reject(new Error(`Failed to parse GSC output: ${err}`));
      }
    });
  });
}
