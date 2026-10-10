import { describe, expect, it } from "vitest";
import { loginContinuation, safeReturnTo } from "./url.ts";

describe("safeReturnTo", () => {
  it("accepts single-leading-slash same-origin paths", () => {
    expect(safeReturnTo("/dashboard")).toStrictEqual("/dashboard");
    expect(safeReturnTo("/a/b?c=d#e")).toStrictEqual("/a/b?c=d#e");
  });

  it("rejects absolute URLs", () => {
    expect(safeReturnTo("https://evil.com")).toStrictEqual("/");
    expect(safeReturnTo("http://evil.com/path")).toStrictEqual("/");
  });

  it("rejects protocol-relative //host", () => {
    expect(safeReturnTo("//evil.com")).toStrictEqual("/");
  });

  it("rejects backslash host tricks /\\host", () => {
    expect(safeReturnTo("/\\evil.com")).toStrictEqual("/");
  });

  it("rejects falsy and non-path values", () => {
    expect(safeReturnTo(undefined)).toStrictEqual("/");
    expect(safeReturnTo(null)).toStrictEqual("/");
    expect(safeReturnTo("")).toStrictEqual("/");
    expect(safeReturnTo("relative/path")).toStrictEqual("/");
  });

  it("uses the provided fallback", () => {
    expect(safeReturnTo("https://evil.com", "/home")).toStrictEqual("/home");
    expect(safeReturnTo(undefined, "/home")).toStrictEqual("/home");
    expect(safeReturnTo("/ok", "/home")).toStrictEqual("/ok");
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
        expect(safeReturnTo(`/${character}/evil.example`)).toStrictEqual("/");
      });

      it(`rejects a ${name} in the /<control>\\host shape`, () => {
        expect(safeReturnTo(`/${character}\\evil.example`)).toStrictEqual("/");
      });

      it(`rejects a ${name} anywhere in an otherwise safe path`, () => {
        expect(safeReturnTo(`/dashboard${character}?a=b`)).toStrictEqual("/");
      });

      it(`falls back to the caller's fallback for a ${name}`, () => {
        expect(
          safeReturnTo(`/${character}/evil.example`, "/home"),
        ).toStrictEqual("/home");
      });
    }
  });

  it("accepts percent-encoded control characters, which browsers do not strip", () => {
    expect(safeReturnTo("/%09/evil.example")).toStrictEqual(
      "/%09/evil.example",
    );
    expect(safeReturnTo("/%0d/evil.example")).toStrictEqual(
      "/%0d/evil.example",
    );
    expect(safeReturnTo("/%0a/evil.example")).toStrictEqual(
      "/%0a/evil.example",
    );
    expect(safeReturnTo("/%2F/evil.example")).toStrictEqual(
      "/%2F/evil.example",
    );
  });

  it("returns unicode paths unchanged", () => {
    expect(safeReturnTo("/caf\u00e9")).toStrictEqual("/caf\u00e9");
    expect(safeReturnTo("/a/b?q=\u00e9#\u00e9")).toStrictEqual(
      "/a/b?q=\u00e9#\u00e9",
    );
  });

  it("rejects a path that resolves to a protocol-relative path", () => {
    expect(safeReturnTo("/..//evil.example")).toStrictEqual("/");
  });

  it("rejects a value the URL parser cannot resolve", () => {
    expect(safeReturnTo("//[")).toStrictEqual("/");
  });

  it("accepts a path that only looks host-like on this origin", () => {
    expect(safeReturnTo("/@evil.example")).toStrictEqual("/@evil.example");
    expect(safeReturnTo("/ /evil.example")).toStrictEqual("/ /evil.example");
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
    expect(loginContinuation(url, opts)).toStrictEqual(url);
  });

  it("matches the authorize path exactly, not by prefix", () => {
    expect(
      loginContinuation("/api/oauth2/authorized-devices", opts),
    ).toStrictEqual(
      "/auth/login?return_to=%2Fapi%2Foauth2%2Fauthorized-devices",
    );
  });

  it("starts a fresh login for a normal path", () => {
    expect(loginContinuation("/dashboard", opts)).toStrictEqual(
      "/auth/login?return_to=%2Fdashboard",
    );
  });

  it("guards open redirects and falls back to the default", () => {
    expect(loginContinuation("https://evil.example/x", opts)).toStrictEqual(
      "/auth/login?return_to=%2Fhome",
    );
    expect(loginContinuation(undefined, opts)).toStrictEqual(
      "/auth/login?return_to=%2Fhome",
    );
  });

  it("works with an absolute authorize endpoint", () => {
    const url = "/oauth2/authorize?x=1";
    expect(
      loginContinuation(url, {
        authorizeEndpoint: "https://idp.example/oauth2/authorize",
      }),
    ).toStrictEqual(url);
  });

  it("falls back to the default for a control-character return_to", () => {
    expect(loginContinuation("/\u0009/evil.example", opts)).toStrictEqual(
      "/auth/login?return_to=%2Fhome",
    );
  });

  it("defaults loginPath and starts fresh when no authorize endpoint is set", () => {
    expect(loginContinuation("/api/oauth2/authorize?x=1")).toStrictEqual(
      "/auth/login?return_to=%2Fapi%2Foauth2%2Fauthorize%3Fx%3D1",
    );
  });
});
