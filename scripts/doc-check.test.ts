import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  extractJsDocExamples,
  extractMarkdownSnippets,
  importPreludeFor,
  isConsumerDependency,
  isFragmentDiagnostic,
  isUndeclaredBinding,
  parseDiagnostics,
  type PublicSymbol,
  type Snippet,
  snippetTsconfig,
  UNDECLARED_BINDING_BASELINE,
} from "./doc-check.ts";

function jsdoc(source: string): ReturnType<typeof extractJsDocExamples> {
  return extractJsDocExamples("server/mod.ts", source);
}

describe("extractMarkdownSnippets", () => {
  it("returns ts and tsx blocks and skips other languages", () => {
    const { snippets } = extractMarkdownSnippets(
      "README.md",
      [
        "```ts",
        "const a = 1;",
        "```",
        "```sh",
        "deno task test",
        "```",
        "```tsx",
        "const b = <p />;",
        "```",
      ].join("\n"),
    );
    expect(snippets.map((s) => s.lang)).toEqual(["ts", "tsx"]);
    expect(snippets[0].origin).toEqual("markdown");
  });

  it("counts an `ignore` block instead of checking it", () => {
    const { snippets, ignored } = extractMarkdownSnippets(
      "README.md",
      ["```ts ignore", "interface Shape { a: string }", "```"].join("\n"),
    );
    expect(snippets).toEqual([]);
    expect(ignored).toEqual(1);
  });

  it("reports the 1-based line of the opening fence", () => {
    const { snippets } = extractMarkdownSnippets(
      "docs/quickstart.md",
      ["intro", "", "```ts", "const a = 1;", "```"].join("\n"),
    );
    expect(snippets[0].fence).toEqual(3);
  });
});

describe("extractJsDocExamples", () => {
  it("returns a fence under @example with the comment markers stripped", () => {
    const { snippets } = jsdoc(
      [
        "/**",
        " * Doc.",
        " *",
        " * @example",
        " * ```ts",
        " * const a = 1;",
        " * ```",
        " */",
        "export const a = 1;",
      ].join("\n"),
    );
    expect(snippets.length).toEqual(1);
    expect(snippets[0].code).toEqual("const a = 1;");
    expect(snippets[0].origin).toEqual("jsdoc");
  });

  it("keeps a fence under a titled @example", () => {
    const { snippets } = jsdoc(
      [
        "/**",
        " * @example Enroll a user",
        " * ```ts",
        " * const a = 1;",
        " * ```",
        " */",
      ].join("\n"),
    );
    expect(snippets.length).toEqual(1);
  });

  it("skips a fence that belongs to a tag other than @example", () => {
    const { snippets } = jsdoc(
      [
        "/**",
        " * @example",
        " * ```ts",
        " * const a = 1;",
        " * ```",
        " *",
        " * @see",
        " * ```ts",
        " * const b = 2;",
        " * ```",
        " */",
      ].join("\n"),
    );
    expect(snippets.map((s) => s.code)).toEqual(["const a = 1;"]);
  });

  it("skips a fence in a doc that has no @example tag", () => {
    const { snippets } = jsdoc(
      ["/**", " * Doc.", " * ```ts", " * const a = 1;", " * ```", " */"].join(
        "\n",
      ),
    );
    expect(snippets).toEqual([]);
  });

  it("skips a fenced block outside any doc comment", () => {
    const { snippets } = jsdoc(
      ["const md = `", "```ts", "const a = 1;", "```", "`;"].join("\n"),
    );
    expect(snippets).toEqual([]);
  });

  it("counts an `ignore` example instead of checking it", () => {
    const { snippets, ignored } = jsdoc(
      [
        "/**",
        " * @example",
        " * ```ts ignore",
        " * pseudo(code);",
        " * ```",
        " */",
      ].join("\n"),
    );
    expect(snippets).toEqual([]);
    expect(ignored).toEqual(1);
  });

  it("returns every example in a file", () => {
    const { snippets } = jsdoc(
      [
        "/**",
        " * @example",
        " * ```ts",
        " * const a = 1;",
        " * ```",
        " */",
        "export const a = 1;",
        "",
        "/**",
        " * @example",
        " * ```tsx",
        " * const b = <p />;",
        " * ```",
        " */",
        "export const b = 2;",
      ].join("\n"),
    );
    expect(snippets.map((s) => s.lang)).toEqual(["ts", "tsx"]);
    expect(snippets.map((s) => s.fence)).toEqual([3, 11]);
  });

  it("does not carry an unterminated example into the next doc comment", () => {
    const { snippets } = jsdoc(
      [
        "/**",
        " * @example",
        " * ```ts",
        " */",
        "export const a = 1;",
        "",
        "/**",
        " * Doc.",
        " */",
      ].join("\n"),
    );
    expect(snippets).toEqual([]);
  });
});

const SYMBOLS: PublicSymbol[] = [
  {
    name: "ResourceServer",
    file: "server/resource-server.ts",
    specifier: "@udibo/oauth2/server",
  },
  {
    name: "ResourceServerOptions",
    file: "server/resource-server.ts",
    specifier: "@udibo/oauth2/server",
  },
  {
    name: "randomToken",
    file: "utils/crypto.ts",
    specifier: "@udibo/oauth2/crypto",
  },
  {
    name: "BasicScope",
    file: "models/scope.ts",
    specifier: "@udibo/oauth2/server",
  },
];

function snippet(code: string, source = "server/resource-server.ts"): Snippet {
  return { source, fence: 1, lang: "ts", code, origin: "jsdoc" };
}

describe("importPreludeFor", () => {
  it("imports the symbols a fragment names from the entrypoint a consumer would use", () => {
    expect(
      importPreludeFor(snippet("const s = new ResourceServer({});"), SYMBOLS),
    ).toEqual('import { ResourceServer } from "@udibo/oauth2/server";');
  });

  it("groups the symbols of one entrypoint into a single import", () => {
    expect(
      importPreludeFor(
        snippet("new ResourceServer({ Scope: BasicScope });"),
        SYMBOLS,
      ),
    ).toEqual(
      'import { BasicScope, ResourceServer } from "@udibo/oauth2/server";',
    );
  });

  it("splits imports across the entrypoints that export them", () => {
    expect(
      importPreludeFor(
        snippet("new ResourceServer({}); randomToken();"),
        SYMBOLS,
      ),
    ).toEqual(
      [
        'import { ResourceServer } from "@udibo/oauth2/server";',
        'import { randomToken } from "@udibo/oauth2/crypto";',
      ].join("\n"),
    );
  });

  it("adds nothing when the fragment names no package symbol", () => {
    expect(
      importPreludeFor(snippet("await app.fetch(request);"), SYMBOLS),
    ).toEqual("");
  });

  it("leaves a symbol the fragment already imports alone", () => {
    expect(
      importPreludeFor(
        snippet(
          'import { randomToken } from "@udibo/oauth2/crypto";\nrandomToken();',
        ),
        SYMBOLS,
      ),
    ).toEqual("");
  });

  it("leaves a name the fragment binds with `declare` alone", () => {
    expect(
      importPreludeFor(
        snippet("declare const randomToken: () => string;\nrandomToken();"),
        SYMBOLS,
      ),
    ).toEqual("");
  });

  it("leaves a name the fragment declares itself alone", () => {
    expect(
      importPreludeFor(
        snippet("class ResourceServer {}\nnew ResourceServer();"),
        SYMBOLS,
      ),
    ).toEqual("");
  });

  it("does not import a name that only appears as part of a longer word", () => {
    expect(
      importPreludeFor(snippet("myResourceServerFactory();"), SYMBOLS),
    ).toEqual("");
  });

  it("resolves a duplicated export through the file the example documents", () => {
    const duplicated: PublicSymbol[] = [
      {
        name: "Token",
        file: "models/token.ts",
        specifier: "@udibo/oauth2/server",
      },
      {
        name: "Token",
        file: "client/mod.ts",
        specifier: "@udibo/oauth2/client",
      },
    ];
    expect(
      importPreludeFor(
        snippet("const t: Token = x;", "client/mod.ts"),
        duplicated,
      ),
    ).toEqual('import { Token } from "@udibo/oauth2/client";');
  });
});

describe("isFragmentDiagnostic", () => {
  it("classifies an undeclared name as fragment-shaped, though the gate still fails it outside the baseline", () => {
    expect(isFragmentDiagnostic("TS2304: Cannot find name 'app'.")).toEqual(
      true,
    );
  });

  it("tolerates a shorthand property with no binding in scope", () => {
    expect(
      isFragmentDiagnostic(
        "TS18004: No value exists in scope for the shorthand property 'tokenService'.",
      ),
    ).toEqual(true);
  });

  it("tolerates a callback parameter left implicitly any by an unbound receiver", () => {
    expect(
      isFragmentDiagnostic(
        "TS7006: Parameter 'c' implicitly has an 'any' type.",
      ),
    ).toEqual(true);
  });

  it("tolerates a bare return, because an example may quote the inside of a handler", () => {
    expect(
      isFragmentDiagnostic(
        "TS1108: A 'return' statement can only be used within a function body.",
      ),
    ).toEqual(true);
  });

  it("fails a relative import the package cannot resolve", () => {
    expect(
      isFragmentDiagnostic(
        "TS2307: Cannot find module './user-service.ts' or its corresponding type declarations.",
      ),
    ).toEqual(false);
  });

  it("fails a property that is not on the documented type", () => {
    expect(
      isFragmentDiagnostic(
        "TS2339: Property 'register' does not exist on type 'UserServiceInterface'.",
      ),
    ).toEqual(false);
  });

  it("fails a wrong argument to a documented call", () => {
    expect(
      isFragmentDiagnostic(
        "TS2345: Argument of type 'Context' is not assignable to parameter of type 'Request'.",
      ),
    ).toEqual(false);
  });
});

describe("isConsumerDependency", () => {
  it("tolerates a third-party module only the reader's app installs", () => {
    expect(
      isConsumerDependency(
        "TS2307: Cannot find module 'bcryptjs' or its corresponding type declarations.",
      ),
    ).toEqual(true);
  });

  it("fails a package subpath that does not resolve", () => {
    expect(
      isConsumerDependency(
        "TS2307: Cannot find module '@udibo/oauth2/identity/mgration' or its corresponding type declarations.",
      ),
    ).toEqual(false);
  });

  it("fails a relative module, which no dependency can supply", () => {
    expect(
      isConsumerDependency(
        "TS2307: Cannot find module './user-service.ts' or its corresponding type declarations.",
      ),
    ).toEqual(false);
  });
});

describe("isUndeclaredBinding", () => {
  it("catches a name an example never declared, because its calls go unchecked", () => {
    expect(isUndeclaredBinding("TS2304: Cannot find name 'server'.")).toEqual(
      true,
    );
  });

  it("catches a misspelled name the compiler offers a suggestion for", () => {
    expect(
      isUndeclaredBinding(
        "TS2552: Cannot find name 'tokenServic'. Did you mean 'tokenService'?",
      ),
    ).toEqual(true);
  });

  it("catches a shorthand property with no binding in scope", () => {
    expect(
      isUndeclaredBinding(
        "TS18004: No value exists in scope for the shorthand property 'tokenService'.",
      ),
    ).toEqual(true);
  });

  it("leaves a bare return alone, which declaring a binding cannot fix", () => {
    expect(
      isUndeclaredBinding(
        "TS1108: A 'return' statement can only be used within a function body.",
      ),
    ).toEqual(false);
  });

  it("leaves a real type error alone, so it is never mistaken for a missing binding", () => {
    expect(
      isUndeclaredBinding(
        "TS2345: Argument of type 'Context' is not assignable to parameter of type 'Request'.",
      ),
    ).toEqual(false);
  });

  it("keeps the baseline free of the files whose examples now declare their bindings", () => {
    expect(
      UNDECLARED_BINDING_BASELINE.has("server/resource-server.ts"),
    ).toEqual(false);
    expect(UNDECLARED_BINDING_BASELINE.has("identity/password.ts")).toEqual(
      false,
    );
  });
});

describe("doc-check's ignore budget", () => {
  it("fails when the opt-outs outnumber the budget, so the count only ratchets down", () => {
    const result = spawnSync(
      process.execPath,
      [
        fileURLToPath(new URL("./doc-check.ts", import.meta.url)),
        "--ignore-budget=0",
      ],
      { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } },
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("exceeds the budget of 0");
  });
});

describe("parseDiagnostics", () => {
  it("names the snippet file and keeps the continuation lines of an error", () => {
    const output = [
      "scripts/doc-check/docs-guides-testing-line29.ts(3,10): error TS2345: Argument of type 'A' is not assignable to parameter of type 'B'.",
      "  Type 'A' is missing the following properties from type 'B': x, y",
      "scripts\\doc-check\\src-server-mod-line8.tsx(1,1): error TS2304: Cannot find name 'app'.",
    ].join("\n");

    expect(parseDiagnostics(output)).toEqual([
      {
        file: "docs-guides-testing-line29.ts",
        text: "TS2345: Argument of type 'A' is not assignable to parameter of type 'B'.\n  Type 'A' is missing the following properties from type 'B': x, y",
      },
      {
        file: "src-server-mod-line8.tsx",
        text: "TS2304: Cannot find name 'app'.",
      },
    ]);
  });

  it("reports a diagnostic with no file as a failure the gate cannot excuse", () => {
    expect(parseDiagnostics("error TS5083: Cannot read file 'x'.")).toEqual([
      { file: null, text: "TS5083: Cannot read file 'x'." },
    ]);
  });
});

describe("snippetTsconfig", () => {
  const config = snippetTsconfig({
    "./server": "./src/server/mod.ts",
    "./hono/bff": "./src/adapters/hono/bff/mod.ts",
  }) as {
    compilerOptions: {
      paths: Record<string, string[]>;
      [key: string]: unknown;
    };
  };

  it("resolves each subpath to the source file the package publishes for it", () => {
    expect(config.compilerOptions.paths).toEqual({
      "@udibo/oauth2/server": ["../../src/server/mod.ts"],
      "@udibo/oauth2/hono/bff": ["../../src/adapters/hono/bff/mod.ts"],
    });
  });

  it("imports a type export without the type modifier, as the prelude writes it", () => {
    expect(config.compilerOptions.verbatimModuleSyntax).toBe(false);
  });
});
