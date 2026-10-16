// ported from GSC gs036_nodejs.py rule GS036-eval_user_input
// ported from GSC gs037_python.py rule GS037-eval_user_input
// ported from GSC gs004_dangerous_subprocess.py rule GS004 (eval/exec on dynamic input)
import type { MatcherPlugin } from "../deepsec-types.js";
import { regexMatcher } from "../utils.js";

export const llmEvalInjectionMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "gsc-llm-eval-injection",
  description: "eval()/new Function()/exec() fed with untrusted or dynamically built input",
  filePatterns: ["**/*.{ts,tsx,js,jsx,py}"],
  examples: [
    `const result = eval(req.query.expr);`,
    `const fn = new Function(req.body.code);`,
    `eval(request.args.get("q"))`,
    `exec(request.json["cmd"])`,
    `eval(f"{user_template}")`,
    `eval(location.hash.slice(1))`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    return regexMatcher(
      "gsc-llm-eval-injection",
      [
        // GS036-eval_user_input: eval/new Function on a known request-like source
        {
          regex:
            /(?:eval|new\s+Function)\s*\(\s*(?:req\.(?:body|query|params|headers|cookies)|request\.(?:body|query|params)|ctx\.request\.(?:body|query)|process\.argv|location\.(?:hash|search)|document\.cookie|URLSearchParams|localStorage\.\w+|window\.name|postMessage|fs\.(?:readFile|readFileSync))/,
          label: "JS eval/new Function on untrusted input (GS036)",
        },
        // GS037-eval_user_input: Python eval() on request/input()
        {
          regex: /eval\s*\(\s*(?:request\.(?:args|form|json|data)|input\s*\()/i,
          label: "Python eval() on request/input() (GS037)",
        },
        // GS037-exec_user_input: Python exec() on request/input()
        {
          regex: /exec\s*\(\s*(?:request\.(?:args|form|json|data)|input\s*\()/i,
          label: "Python exec() on request/input() (GS037)",
        },
        // GS004: eval() on dynamically built string (f-string / .format)
        {
          regex: /eval\s*\(\s*(?:.*f["']|.*\.format\()/,
          label: "eval() on dynamically built string (GS004)",
        },
        // GS004: exec() on a variable rather than a triple-quoted literal
        {
          regex: /exec\s*\(\s*(?!["']{3})\w/,
          label: "exec() on variable — code injection risk (GS004)",
        },
      ],
      content,
    );
  },
};
