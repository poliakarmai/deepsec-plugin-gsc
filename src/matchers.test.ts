import { describe, expect, it } from "vitest";
import gscPlugin from "./index.js";
import { llmEvalInjectionMatcher } from "./matchers/llm-eval-injection.js";
import { llmNosqlInjectionMatcher } from "./matchers/llm-nosql-injection.js";
import { llmCommandInjectionMatcher } from "./matchers/llm-command-injection.js";
import { regexMatcher } from "./utils.js";

const JS = "src/app.js";
const PY = "src/app.py";

describe("gsc-llm-eval-injection", () => {
  it("flags eval() on req.query", () => {
    const hits = llmEvalInjectionMatcher.match(
      "const result = eval(req.query.expr);",
      JS,
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].vulnSlug).toBe("gsc-llm-eval-injection");
    expect(hits[0].lineNumbers).toEqual([1]);
    expect(hits[0].matchedPattern).toContain("GS036");
  });

  it("flags python exec() on request.json", () => {
    const hits = llmEvalInjectionMatcher.match(
      'exec(request.json["cmd"])',
      PY,
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].matchedPattern).toContain("GS037");
  });

  it("flags eval() on an f-string (GS004)", () => {
    const hits = llmEvalInjectionMatcher.match('eval(f"{user_template}")', PY);
    expect(hits).toHaveLength(1);
    expect(hits[0].matchedPattern).toContain("GS004");
  });

  it("ignores eval() on a literal", () => {
    expect(llmEvalInjectionMatcher.match('const n = eval("2+2");', JS)).toEqual(
      [],
    );
  });

  it("ignores test files", () => {
    expect(
      llmEvalInjectionMatcher.match("eval(req.query.expr)", "src/app.test.js"),
    ).toEqual([]);
  });
});

describe("gsc-llm-nosql-injection", () => {
  it("flags a $where operator in a query object", () => {
    const hits = llmNosqlInjectionMatcher.match(
      `db.users.find({ $where: "this.role == 'admin'" });`,
      JS,
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].vulnSlug).toBe("gsc-llm-nosql-injection");
  });

  it("flags a query predicate fed raw req.query", () => {
    const hits = llmNosqlInjectionMatcher.match(
      "await User.update(req.query.id, req.body);",
      JS,
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].matchedPattern).toContain("raw req.body/req.query");
  });

  it("ignores a query with a plain literal predicate", () => {
    expect(
      llmNosqlInjectionMatcher.match('db.users.find({ role: "admin" });', JS),
    ).toEqual([]);
  });
});

describe("gsc-llm-command-injection", () => {
  it("flags exec() concatenated with req.query", () => {
    const hits = llmCommandInjectionMatcher.match(
      'exec("ls " + req.query.dir, cb);',
      JS,
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].vulnSlug).toBe("gsc-llm-command-injection");
    expect(hits[0].matchedPattern).toContain("GS036");
  });

  it("flags os.system() on an f-string", () => {
    const hits = llmCommandInjectionMatcher.match('os.system(f"ping {host}")', PY);
    expect(hits).toHaveLength(1);
    expect(hits[0].matchedPattern).toContain("GS037");
  });

  it("ignores exec() on a literal", () => {
    expect(llmCommandInjectionMatcher.match('exec("ls");', JS)).toEqual([]);
  });
});

describe("regexMatcher helper", () => {
  it("reports 1-based line numbers and a +/-2 line snippet", () => {
    const content = ["a", "b", "eval(req.body.x)", "d", "e"].join("\n");
    const [hit] = regexMatcher(
      "slug",
      [{ regex: /eval\(/, label: "test label" }],
      content,
    );
    expect(hit.lineNumbers).toEqual([3]);
    expect(hit.snippet).toBe("a\nb\neval(req.body.x)\nd\ne");
    expect(hit.matchedPattern).toBe("test label");
  });

  it("groups multiple matching lines of one pattern into a single match", () => {
    const content = ["eval(req.body.a)", "eval(req.query.b)"].join("\n");
    const hits = regexMatcher(
      "slug",
      [{ regex: /eval\(/, label: "l" }],
      content,
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].lineNumbers).toEqual([1, 2]);
  });
});

describe("gscPlugin()", () => {
  it("registers three matchers and one notifier", () => {
    const plugin = gscPlugin();
    expect(plugin.name).toBe("@poliakarm/plugin-gsc");
    expect(plugin.matchers?.map((m) => m.slug)).toEqual([
      "gsc-llm-eval-injection",
      "gsc-llm-nosql-injection",
      "gsc-llm-command-injection",
    ]);
    expect(plugin.notifiers).toHaveLength(1);
  });
});
