import type { DeepsecPlugin } from "./deepsec-types.js";
import { llmEvalInjectionMatcher } from "./matchers/llm-eval-injection.js";
import { llmNosqlInjectionMatcher } from "./matchers/llm-nosql-injection.js";
import { llmCommandInjectionMatcher } from "./matchers/llm-command-injection.js";
import { gscVerifyNotifier } from "./notifier.js";

export interface GscPluginOptions {
  gscPath?: string;
  telemetry?: boolean;
}

export default function gscPlugin(opts?: GscPluginOptions): DeepsecPlugin {
  return {
    name: "@poliakarm/plugin-gsc",
    matchers: [
      llmEvalInjectionMatcher,
      llmNosqlInjectionMatcher,
      llmCommandInjectionMatcher,
    ],
    notifiers: [gscVerifyNotifier(opts)],
  };
}
