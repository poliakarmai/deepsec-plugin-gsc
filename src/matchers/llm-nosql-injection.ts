// ported from GSC gs036_nodejs.py rule GS036-nosql_injection_where
// ported from GSC gs036_nodejs.py rule GS036-nosql_injection_user_input
import type { MatcherPlugin } from "../deepsec-types.js";
import { regexMatcher } from "../utils.js";

export const llmNosqlInjectionMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "gsc-llm-nosql-injection",
  description: "NoSQL operator injection ($where/$ne/...) and Mongo queries fed with raw request input",
  filePatterns: ["**/*.{ts,tsx,js,jsx}"],
  examples: [
    `db.users.find({ $where: "this.role == 'admin'" });`,
    `const opts = { $ne: null, $gt: 0 };`,
    `db.collection("users").findOne(req.body.filter);`,
    `await User.update(req.query.id, req.body);`,
    `db.sessions.deleteOne(req.query);`,
  ],
  match(content, filePath) {
    if (/\.(test|spec)\./i.test(filePath)) return [];

    return regexMatcher(
      "gsc-llm-nosql-injection",
      [
        // GS036-nosql_injection_where: raw Mongo operator keys from a crafted object
        {
          regex: /\$(?:where|regex|ne|gt|lt|in|nin)\s*:/,
          label: "NoSQL operator in query object ($where/$ne/...) — verify input not user-supplied (GS036)",
        },
        // GS036-nosql_injection_user_input: query predicates taking req.body/req.query directly
        {
          regex: /(?:\.find|\.findOne|\.update|\.deleteOne)\s*\(\s*req\.(?:body|query)/,
          label: "Mongo query predicate fed raw req.body/req.query (GS036)",
        },
      ],
      content,
    );
  },
};
