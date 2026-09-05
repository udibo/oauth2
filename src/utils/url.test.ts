import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { loginContinuation, safeReturnTo } from "./url.ts";

describe("safeReturnTo", () => {
  it("accepts single-leading-slash same-origin paths", () => {
    assertEquals(safeReturnTo("/dashboard"), "/dashboard");
    assertEquals(safeReturnTo("/a/b?c=d#e"), "/a/b?c=d#e");
  });

  it("rejects absolute URLs", () => {
    assertEquals(safeReturnTo("https://evil.com"), "/");
    assertEquals(safeReturnTo("http://evil.com/path"), "/");
  });

  it("rejects protocol-relative //host", () => {
    assertEquals(safeReturnTo("//evil.com"), "/");
  });

  it("rejects backslash host tricks /\\host", () => {
    assertEquals(safeReturnTo("/\\evil.com"), "/");
  });

  it("rejects falsy and non-path values", () => {
    assertEquals(safeReturnTo(undefined), "/");
    assertEquals(safeReturnTo(null), "/");
    assertEquals(safeReturnTo(""), "/");
    assertEquals(safeReturnTo("relative/path"), "/");
  });

  it("uses the provided fallback", () => {
    assertEquals(safeReturnTo("https://evil.com", "/home"), "/home");
    assertEquals(safeReturnTo(undefined, "/home"), "/home");
    assertEquals(safeReturnTo("/ok", "/home"), "/ok");
  });

  const CONTROL_CHARACTERS: [string, string][] = [
    ["tab", "\u0009"],
    ["carriage return", "\u000d"],
    ["line feed", "\u000a"],
    ["null", "\u0000"],
    ["delete", "\u007f"],
    ["vertical tab", "\u000b"],
    ["form feed", "\u000c"],
  ];

  describe("rejects embedded control characters", () => {
    for (const [name, character] of CONTROL_CHARACTERS) {
      it(`rejects a ${name} in the /<control>/host shape`, () => {
        assertEquals(safeReturnTo(`/${character}/evil.example`), "/");
      });

      it(`rejects a ${name} in the /<control>\\host shape`, () => {
        assertEquals(safeReturnTo(`/${character}\\evil.example`), "/");
      });

      it(`rejects a ${name} anywhere in an otherwise safe path`, () => {
        assertEquals(safeReturnTo(`/dashboard${character}?a=b`), "/");
      });

      it(`falls back to the caller's fallback for a ${name}`, () => {
        assertEquals(
          safeReturnTo(`/${character}/evil.example`, "/home"),
          "/home",
        );
      });
    }
  });

  it("accepts percent-encoded control characters, which browsers do not strip", () => {
    assertEquals(safeReturnTo("/%09/evil.example"), "/%09/evil.example");
    assertEquals(safeReturnTo("/%0d/evil.example"), "/%0d/evil.example");
    assertEquals(safeReturnTo("/%0a/evil.example"), "/%0a/evil.example");
    assertEquals(safeReturnTo("/%2F/evil.example"), "/%2F/evil.example");
  });

  it("returns unicode paths unchanged", () => {
    assertEquals(safeReturnTo("/caf\u00e9"), "/caf\u00e9");
    assertEquals(safeReturnTo("/a/b?q=\u00e9#\u00e9"), "/a/b?q=\u00e9#\u00e9");
  });

  it("rejects a path that resolves to a protocol-relative path", () => {
    assertEquals(safeReturnTo("/..//evil.example"), "/");
  });

  it("rejects a value the URL parser cannot resolve", () => {
    assertEquals(safeReturnTo("//["), "/");
  });

  it("accepts a path that only looks host-like on this origin", () => {
    assertEquals(safeReturnTo("/@evil.example"), "/@evil.example");
    assertEquals(safeReturnTo("/ /evil.example"), "/ /evil.example");
  });
});

describe("loginContinuation", () => {
  const opts = {
    authorizeEndpoint: "/api/oauth2/authorize",
    loginPath: "/auth/login",
    defaultReturnTo: "/home",
  };

  it("resumes an in-flight authorize URL unchanged", () => {
    const url = "/api/oauth2/authorize?response_type=code&state=abc";
    assertEquals(loginContinuation(url, opts), url);
  });

  it("matches the authorize path exactly, not by prefix", () => {
    assertEquals(
      loginContinuation("/api/oauth2/authorized-devices", opts),
      "/auth/login?return_to=%2Fapi%2Foauth2%2Fauthorized-devices",
    );
  });

  it("starts a fresh login for a normal path", () => {
    assertEquals(
      loginContinuation("/dashboard", opts),
      "/auth/login?return_to=%2Fdashboard",
    );
  });

  it("guards open redirects and falls back to the default", () => {
    assertEquals(
      loginContinuation("https://evil.example/x", opts),
      "/auth/login?return_to=%2Fhome",
    );
    assertEquals(
      loginContinuation(undefined, opts),
      "/auth/login?return_to=%2Fhome",
    );
  });

  it("works with an absolute authorize endpoint", () => {
    const url = "/oauth2/authorize?x=1";
    assertEquals(
      loginContinuation(url, {
        authorizeEndpoint: "https://idp.example/oauth2/authorize",
      }),
      url,
    );
  });

  it("falls back to the default for a control-character return_to", () => {
    assertEquals(
      loginContinuation("/\u0009/evil.example", opts),
      "/auth/login?return_to=%2Fhome",
    );
  });

  it("defaults loginPath and starts fresh when no authorize endpoint is set", () => {
    assertEquals(
      loginContinuation("/api/oauth2/authorize?x=1"),
      "/auth/login?return_to=%2Fapi%2Foauth2%2Fauthorize%3Fx%3D1",
    );
  });
});
