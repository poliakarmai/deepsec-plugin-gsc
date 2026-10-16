// ported from GSC gs036_nodejs.py rule GS036-command_injection_exec
// ported from GSC gs036_nodejs.py rule GS036-command_injection_shell
// ported from GSC gs037_python.py rule GS037-command_injection_os
// ported from GSC gs037_python.py rule GS037-command_injection_subprocess
// ported from GSC gs037_python.py rule GS037-command_injection_shell_true
// ported from GSC gs004_dangerous_subprocess.py rule GS004 (os.system %/.format)
import type { MatcherPlugin } from "../deepsec-types.js";
import { regexMatcher } from "../utils.js";

export const llmCommandInjectionMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "gsc-llm-command-injection",
  description: "Shell command construction from untrusted input (child_process/os.system/subprocess)",
  filePatterns: ["**/*.{ts,tsx,js,jsx,py}"],
  examples: [
    `exec("ls " + req.query.dir, cb);`,
    `execSync("git clone " + process.argv[2]);`,
    `child_process.exec(cmd, { shell: true });`,
    `os.system(f"ping {host}")`,
    `subprocess.run(cmd, shell=True)`,
    `os.system("rm -rf %s" % target)`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    return regexMatcher(
      "gsc-llm-command-injection",
      [
        // GS036-command_injection_exec: exec/spawn receiving request input or argv
        {
          regex: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*[^)]*(?:req\.(?:body|query|params)|process\.argv)/,
          label: "child_process exec/spawn with req.*/process.argv (GS036)",
        },
        // GS036-command_injection_shell: exec with shell:true options object
        {
          regex: /(?:exec|execSync)\s*\([^,]*,[^{]*\{[^}]*shell\s*:\s*true/,
          label: "child_process exec with shell:true (GS036)",
        },
        // GS037-command_injection_os: os.system/os.popen on request input or f-string
        {
          regex: /os\.(?:system|popen)\s*\(\s*(?:request\.(?:args|form|json|data)|f["'])/i,
          label: "os.system/os.popen on request input or f-string (GS037)",
        },
        // GS037-command_injection_subprocess: subprocess.* with request input
        {
          regex: /subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*(?:request\.|input\s*\()/i,
          label: "subprocess.* with request input (GS037)",
        },
        // GS037-command_injection_shell_true: shell=True anywhere in the call
        {
          regex: /subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True/i,
          label: "subprocess.* with shell=True (GS037)",
        },
        // GS004: os.system with %-formatting
        {
          regex: /os\.system\s*\(\s*["'][^"']*%[sd]/,
          label: "os.system() with %-formatting (GS004)",
        },
        // GS004: os.system with .format()
        {
          regex: /os\.system\s*\(\s*["'][^"']*\.format\(/,
          label: "os.system() with .format() (GS004)",
        },
      ],
      content,
    );
  },
};
