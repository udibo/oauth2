import { assertEquals, assertStringIncludes } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  extractJsDocExamples,
  extractMarkdownSnippets,
  importPreludeFor,
  isConsumerDependency,
  isFragmentDiagnostic,
  isUndeclaredBinding,
  type PublicSymbol,
  type Snippet,
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
    assertEquals(snippets.map((s) => s.lang), ["ts", "tsx"]);
    assertEquals(snippets[0].origin, "markdown");
  });

  it("counts an `ignore` block instead of checking it", () => {
    const { snippets, ignored } = extractMarkdownSnippets(
      "README.md",
      ["```ts ignore", "interface Shape { a: string }", "```"].join("\n"),
    );
    assertEquals(snippets, []);
    assertEquals(ignored, 1);
  });

  it("reports the 1-based line of the opening fence", () => {
    const { snippets } = extractMarkdownSnippets(
      "docs/quickstart.md",
      ["intro", "", "```ts", "const a = 1;", "```"].join("\n"),
    );
    assertEquals(snippets[0].fence, 3);
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
    assertEquals(snippets.length, 1);
    assertEquals(snippets[0].code, "const a = 1;");
    assertEquals(snippets[0].origin, "jsdoc");
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
    assertEquals(snippets.length, 1);
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
    assertEquals(snippets.map((s) => s.code), ["const a = 1;"]);
  });

  it("skips a fence in a doc that has no @example tag", () => {
    const { snippets } = jsdoc(
      ["/**", " * Doc.", " * ```ts", " * const a = 1;", " * ```", " */"].join(
        "\n",
      ),
    );
    assertEquals(snippets, []);
  });

  it("skips a fenced block outside any doc comment", () => {
    const { snippets } = jsdoc(
      ["const md = `", "```ts", "const a = 1;", "```", "`;"].join("\n"),
    );
    assertEquals(snippets, []);
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
    assertEquals(snippets, []);
    assertEquals(ignored, 1);
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
    assertEquals(snippets.map((s) => s.lang), ["ts", "tsx"]);
    assertEquals(snippets.map((s) => s.fence), [3, 11]);
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
    assertEquals(snippets, []);
  });
});

const SYMBOLS: PublicSymbol[] = [
  {
    name: "ResourceServer",
    kind: "class",
    file: "server/resource-server.ts",
    specifier: "@udibo/oauth2/server",
  },
  {
    name: "ResourceServerOptions",
    kind: "interface",
    file: "server/resource-server.ts",
    specifier: "@udibo/oauth2/server",
  },
  {
    name: "randomToken",
    kind: "function",
    file: "utils/crypto.ts",
    specifier: "@udibo/oauth2/crypto",
  },
  {
    name: "BasicScope",
    kind: "class",
    file: "models/scope.ts",
    specifier: "@udibo/oauth2/server",
  },
];

function snippet(code: string, source = "server/resource-server.ts"): Snippet {
  return { source, fence: 1, lang: "ts", code, origin: "jsdoc" };
}

describe("importPreludeFor", () => {
  it("imports the symbols a fragment names from the entrypoint a consumer would use", () => {
    assertEquals(
      importPreludeFor(snippet("const s = new ResourceServer({});"), SYMBOLS),
      'import { ResourceServer } from "@udibo/oauth2/server";',
    );
  });

  it("groups the symbols of one entrypoint into a single import", () => {
    assertEquals(
      importPreludeFor(
        snippet("new ResourceServer({ Scope: BasicScope });"),
        SYMBOLS,
      ),
      'import { BasicScope, ResourceServer } from "@udibo/oauth2/server";',
    );
  });

  it("splits imports across the entrypoints that export them", () => {
    assertEquals(
      importPreludeFor(
        snippet("new ResourceServer({}); randomToken();"),
        SYMBOLS,
      ),
      [
        'import { ResourceServer } from "@udibo/oauth2/server";',
        'import { randomToken } from "@udibo/oauth2/crypto";',
      ].join("\n"),
    );
  });

  it("imports a type export with the `type` modifier", () => {
    assertEquals(
      importPreludeFor(snippet("const o: ResourceServerOptions = x;"), SYMBOLS),
      'import { type ResourceServerOptions } from "@udibo/oauth2/server";',
    );
  });

  it("adds nothing when the fragment names no package symbol", () => {
    assertEquals(
      importPreludeFor(snippet("await app.fetch(request);"), SYMBOLS),
      "",
    );
  });

  it("leaves a symbol the fragment already imports alone", () => {
    assertEquals(
      importPreludeFor(
        snippet(
          'import { randomToken } from "@udibo/oauth2/crypto";\nrandomToken();',
        ),
        SYMBOLS,
      ),
      "",
    );
  });

  it("leaves a name the fragment binds with `declare` alone", () => {
    assertEquals(
      importPreludeFor(
        snippet("declare const randomToken: () => string;\nrandomToken();"),
        SYMBOLS,
      ),
      "",
    );
  });

  it("leaves a name the fragment declares itself alone", () => {
    assertEquals(
      importPreludeFor(
        snippet("class ResourceServer {}\nnew ResourceServer();"),
        SYMBOLS,
      ),
      "",
    );
  });

  it("does not import a name that only appears as part of a longer word", () => {
    assertEquals(
      importPreludeFor(snippet("myResourceServerFactory();"), SYMBOLS),
      "",
    );
  });

  it("resolves a duplicated export through the file the example documents", () => {
    const duplicated: PublicSymbol[] = [
      {
        name: "Token",
        kind: "interface",
        file: "models/token.ts",
        specifier: "@udibo/oauth2/server",
      },
      {
        name: "Token",
        kind: "interface",
        file: "client/mod.ts",
        specifier: "@udibo/oauth2/client",
      },
    ];
    assertEquals(
      importPreludeFor(
        snippet("const t: Token = x;", "client/mod.ts"),
        duplicated,
      ),
      'import { type Token } from "@udibo/oauth2/client";',
    );
  });
});

describe("isFragmentDiagnostic", () => {
  it("classifies an undeclared name as fragment-shaped, though the gate still fails it outside the baseline", () => {
    assertEquals(
      isFragmentDiagnostic("TS2304 [ERROR]: Cannot find name 'app'."),
      true,
    );
  });

  it("tolerates a shorthand property with no binding in scope", () => {
    assertEquals(
      isFragmentDiagnostic(
        "TS18004 [ERROR]: No value exists in scope for the shorthand property 'tokenService'.",
      ),
      true,
    );
  });

  it("tolerates a callback parameter left implicitly any by an unbound receiver", () => {
    assertEquals(
      isFragmentDiagnostic(
        "TS7006 [ERROR]: Parameter 'c' implicitly has an 'any' type.",
      ),
      true,
    );
  });

  it("tolerates a bare return, because an example may quote the inside of a handler", () => {
    assertEquals(
      isFragmentDiagnostic(
        "TS1108 [ERROR]: A 'return' statement can only be used within a function body.",
      ),
      true,
    );
  });

  it("fails a relative import the package cannot resolve", () => {
    assertEquals(
      isFragmentDiagnostic(
        "TS2307 [ERROR]: Cannot find module './user-service.ts'.",
      ),
      false,
    );
  });

  it("fails a property that is not on the documented type", () => {
    assertEquals(
      isFragmentDiagnostic(
        "TS2339 [ERROR]: Property 'register' does not exist on type 'UserServiceInterface'.",
      ),
      false,
    );
  });

  it("fails a wrong argument to a documented call", () => {
    assertEquals(
      isFragmentDiagnostic(
        "TS2345 [ERROR]: Argument of type 'Context' is not assignable to parameter of type 'Request'.",
      ),
      false,
    );
  });
});

describe("isConsumerDependency", () => {
  it("tolerates a third-party module only the reader's app installs", () => {
    assertEquals(
      isConsumerDependency(
        'TS2307 [ERROR]: Import "bcryptjs" not a dependency and not in import map from "file:///x.ts"',
      ),
      true,
    );
  });

  it("fails a package subpath that does not resolve", () => {
    assertEquals(
      isConsumerDependency(
        'TS2307 [ERROR]: Import "@udibo/oauth2/identity/mgration" not a dependency and not in import map from "file:///x.ts"',
      ),
      false,
    );
  });

  it("fails a relative module, which no dependency can supply", () => {
    assertEquals(
      isConsumerDependency(
        "TS2307 [ERROR]: Cannot find module './user-service.ts'.",
      ),
      false,
    );
  });
});

describe("isUndeclaredBinding", () => {
  it("catches a name an example never declared, because its calls go unchecked", () => {
    assertEquals(
      isUndeclaredBinding("TS2304 [ERROR]: Cannot find name 'server'."),
      true,
    );
  });

  it("catches a misspelled name the compiler offers a suggestion for", () => {
    assertEquals(
      isUndeclaredBinding(
        "TS2552 [ERROR]: Cannot find name 'tokenServic'. Did you mean 'tokenService'?",
      ),
      true,
    );
  });

  it("catches a shorthand property with no binding in scope", () => {
    assertEquals(
      isUndeclaredBinding(
        "TS18004 [ERROR]: No value exists in scope for the shorthand property 'tokenService'.",
      ),
      true,
    );
  });

  it("leaves a bare return alone, which declaring a binding cannot fix", () => {
    assertEquals(
      isUndeclaredBinding(
        "TS1108 [ERROR]: A 'return' statement can only be used within a function body.",
      ),
      false,
    );
  });

  it("leaves a real type error alone, so it is never mistaken for a missing binding", () => {
    assertEquals(
      isUndeclaredBinding(
        "TS2345 [ERROR]: Argument of type 'Context' is not assignable to parameter of type 'Request'.",
      ),
      false,
    );
  });

  it("keeps the baseline free of the files whose examples now declare their bindings", () => {
    assertEquals(
      UNDECLARED_BINDING_BASELINE.has("server/resource-server.ts"),
      false,
    );
    assertEquals(
      UNDECLARED_BINDING_BASELINE.has("identity/password.ts"),
      false,
    );
  });
});

describe("doc-check's ignore budget", () => {
  it("fails when the opt-outs outnumber the budget, so the count only ratchets down", async () => {
    const { code, stderr } = await new Deno.Command(Deno.execPath(), {
      args: [
        "run",
        "--allow-read",
        "--allow-write",
        "--allow-run",
        new URL("./doc-check.ts", import.meta.url).href,
        "--ignore-budget=9",
      ],
      cwd: new URL("../", import.meta.url),
      env: { NO_COLOR: "1" },
    }).output();

    assertEquals(code, 1);
    assertStringIncludes(
      new TextDecoder().decode(stderr),
      "exceeds the budget of 9",
    );
  });
});
