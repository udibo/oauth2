import { describe, expect, it } from "vitest";
import { thrown } from "../_test_assert.ts";
import { InvalidClientError } from "../errors.ts";
import {
  encodeBasicAuth,
  parseBasicAuth,
  tryParseBasicAuth,
} from "./basic-auth.ts";

describe("parseBasicAuth", () => {
  describe("authorization header required", () => {
    it("should throw for null authorization", () => {
      thrown(
        () => parseBasicAuth(null),
        InvalidClientError,
        "authorization header required",
      );
    });

    it("should throw for empty string authorization", () => {
      thrown(
        () => parseBasicAuth(""),
        InvalidClientError,
        "authorization header required",
      );
    });
  });

  describe("unsupported authorization header", () => {
    it("should throw for single word", () => {
      thrown(
        () => parseBasicAuth("x"),
        InvalidClientError,
        "unsupported authorization header",
      );
    });

    it("should throw for basic without credentials", () => {
      thrown(
        () => parseBasicAuth("basic"),
        InvalidClientError,
        "unsupported authorization header",
      );
    });

    it("should throw for Bearer auth", () => {
      thrown(
        () => parseBasicAuth("Bearer mF_9.B5f-4.1JqM"),
        InvalidClientError,
        "unsupported authorization header",
      );
    });
  });

  describe("authorization header is not correctly encoded", () => {
    it("should throw for invalid base64", () => {
      thrown(
        () => parseBasicAuth("basic x"),
        InvalidClientError,
        "authorization header is not correctly encoded",
      );
    });

    it("should throw for invalid padding", () => {
      thrown(
        () => parseBasicAuth(`basic ${btoa("kyle")}=`),
        InvalidClientError,
        "authorization header is not correctly encoded",
      );
    });
  });

  describe("authorization header is malformed", () => {
    it("should throw for missing colon", () => {
      thrown(
        () => parseBasicAuth(`basic ${btoa("kyle")}`),
        InvalidClientError,
        "authorization header is malformed",
      );
    });

    it("should throw for empty username", () => {
      thrown(
        () => parseBasicAuth(`basic ${btoa(":")}`),
        InvalidClientError,
        "authorization header is malformed",
      );
    });

    it("should throw for colon only with password", () => {
      thrown(
        () => parseBasicAuth(`basic ${btoa(":hunter2")}`),
        InvalidClientError,
        "authorization header is malformed",
      );
    });
  });

  describe("returns correct credentials", () => {
    it("should parse username without password", () => {
      const basicAuth = parseBasicAuth(`basic ${btoa("kyle:")}`);
      expect(basicAuth).toStrictEqual({ name: "kyle", pass: "" });
    });

    it("should parse username and password", () => {
      const basicAuth = parseBasicAuth(`BASIC ${btoa("kyle:hunter2")}`);
      expect(basicAuth).toStrictEqual({ name: "kyle", pass: "hunter2" });
    });

    it("should be case insensitive for Basic", () => {
      const basicAuth = parseBasicAuth(`BaSiC ${btoa("Kyle:Hunter2")}`);
      expect(basicAuth).toStrictEqual({ name: "Kyle", pass: "Hunter2" });
    });

    it("should handle password with colons", () => {
      const basicAuth = parseBasicAuth(
        `basic ${btoa("user:pass:with:colons")}`,
      );
      expect(basicAuth).toStrictEqual({
        name: "user",
        pass: "pass:with:colons",
      });
    });

    it("decodes form-urlencoded credentials", () => {
      const basicAuth = parseBasicAuth(
        `basic ${btoa("caf%C3%A9:p%2Bss%3Aw%25d")}`,
      );
      expect(basicAuth).toStrictEqual({ name: "caf\u00e9", pass: "p+ss:w%d" });
    });

    it("decodes a plus as a space", () => {
      const basicAuth = parseBasicAuth(`basic ${btoa("kyle:hunter+2")}`);
      expect(basicAuth).toStrictEqual({ name: "kyle", pass: "hunter 2" });
    });

    it("keeps a segment verbatim when it is not valid percent-encoding", () => {
      const basicAuth = parseBasicAuth(`basic ${btoa("kyle:100%off")}`);
      expect(basicAuth).toStrictEqual({ name: "kyle", pass: "100%off" });
    });
  });
});

describe("encodeBasicAuth", () => {
  it("should encode credentials correctly", () => {
    const encoded = encodeBasicAuth("kyle", "hunter2");
    expect(encoded).toBe(`Basic ${btoa("kyle:hunter2")}`);
  });

  it("should handle empty password", () => {
    const encoded = encodeBasicAuth("kyle", "");
    expect(encoded).toBe(`Basic ${btoa("kyle:")}`);
  });

  it("form-urlencodes reserved characters per RFC 6749 section 2.3.1", () => {
    const encoded = encodeBasicAuth("user@example.com", "p@ss:w0rd!");
    expect(encoded).toBe(
      `Basic ${btoa("user%40example.com:p%40ss%3Aw0rd%21")}`,
    );
  });

  it("leaves alphanumeric credentials byte-identical to the raw form", () => {
    expect(encodeBasicAuth("client1", "abc123XYZ")).toBe(
      `Basic ${btoa("client1:abc123XYZ")}`,
    );
    expect(encodeBasicAuth("my-client_9.a", "s-e_c.r*et")).toBe(
      `Basic ${btoa("my-client_9.a:s-e_c.r*et")}`,
    );
  });

  it("encodes each credential exactly as the application/x-www-form-urlencoded serializer does", () => {
    const clientId = "id \u00e9+:%~!*'()-._";
    const clientSecret = "secret \u00e9+:%";
    expect(encodeBasicAuth(clientId, clientSecret)).toBe(
      `Basic ${btoa(
        `${new URLSearchParams({ v: clientId }).toString().slice(2)}:${new URLSearchParams(
          { v: clientSecret },
        )
          .toString()
          .slice(2)}`,
      )}`,
    );
  });

  it("encodes a plus in the secret so it is not decoded as a space", () => {
    expect(encodeBasicAuth("client", "a+b")).toBe(
      `Basic ${btoa("client:a%2Bb")}`,
    );
  });

  it("encodes a space in the secret as a plus", () => {
    expect(encodeBasicAuth("client", "a b")).toBe(
      `Basic ${btoa("client:a+b")}`,
    );
  });

  it("encodes a percent sign in the secret", () => {
    expect(encodeBasicAuth("client", "100%off")).toBe(
      `Basic ${btoa("client:100%25off")}`,
    );
  });

  it("encodes a colon in the client id so the split stays unambiguous", () => {
    expect(encodeBasicAuth("a:b", "secret")).toBe(
      `Basic ${btoa("a%3Ab:secret")}`,
    );
    expect(parseBasicAuth(encodeBasicAuth("a:b", "secret"))).toStrictEqual({
      name: "a:b",
      pass: "secret",
    });
  });

  it("encodes a secret above U+00FF, which btoa alone cannot represent", () => {
    expect(encodeBasicAuth("client", "\u20ac\u65e5")).toBe(
      `Basic ${btoa("client:%E2%82%AC%E6%97%A5")}`,
    );
  });

  it("encodes a non-ASCII secret instead of throwing", () => {
    expect(encodeBasicAuth("client", "caf\u00e9")).toBe(
      `Basic ${btoa("client:caf%C3%A9")}`,
    );
  });
});

describe("encodeBasicAuth and parseBasicAuth round trip", () => {
  const credentials: [string, string][] = [
    ["client1", "abc123XYZ"],
    ["client", "a+b"],
    ["client", "a b"],
    ["client", "100%off"],
    ["client", "pa:ss"],
    ["a:b", "c:d"],
    ["caf\u00e9", "caf\u00e9 \u00fc\u00df"],
    ["client", "\u20ac\u65e5 secret"],
    ["client", "%2Bnot-decoded-twice"],
    ["client", ""],
  ];

  for (const [clientId, clientSecret] of credentials) {
    it(`recovers ${JSON.stringify(clientId)} / ${JSON.stringify(clientSecret)}`, () => {
      const header = encodeBasicAuth(clientId, clientSecret);
      expect(parseBasicAuth(header)).toStrictEqual({
        name: clientId,
        pass: clientSecret,
      });
      expect(tryParseBasicAuth(header)).toStrictEqual({
        name: clientId,
        pass: clientSecret,
      });
    });
  }
});

describe("tryParseBasicAuth", () => {
  it("should return undefined for null authorization", () => {
    expect(tryParseBasicAuth(null)).toBe(undefined);
  });

  it("should return undefined for empty string", () => {
    expect(tryParseBasicAuth("")).toBe(undefined);
  });

  it("should return undefined for non-Basic auth", () => {
    expect(tryParseBasicAuth("Bearer token")).toBe(undefined);
  });

  it("should return undefined for non-matching format", () => {
    expect(tryParseBasicAuth("basic invalid!!!")).toBe(undefined);
  });

  it("should return undefined when atob throws on regex-matching invalid base64", () => {
    expect(tryParseBasicAuth("basic a=")).toBe(undefined);
  });

  it("should return undefined for malformed credentials", () => {
    expect(tryParseBasicAuth(`basic ${btoa("nocolon")}`)).toBe(undefined);
  });

  it("should return undefined for empty username", () => {
    expect(tryParseBasicAuth(`basic ${btoa(":pass")}`)).toBe(undefined);
  });

  it("should return credentials for valid Basic auth", () => {
    const result = tryParseBasicAuth(`basic ${btoa("user:pass")}`);
    expect(result).toStrictEqual({ name: "user", pass: "pass" });
  });

  it("should handle empty password", () => {
    const result = tryParseBasicAuth(`basic ${btoa("user:")}`);
    expect(result).toStrictEqual({ name: "user", pass: "" });
  });

  it("decodes form-urlencoded credentials", () => {
    const result = tryParseBasicAuth(`basic ${btoa("caf%C3%A9:p%2Bss")}`);
    expect(result).toStrictEqual({ name: "caf\u00e9", pass: "p+ss" });
  });

  it("keeps a segment verbatim when it is not valid percent-encoding", () => {
    const result = tryParseBasicAuth(`basic ${btoa("user:100%off")}`);
    expect(result).toStrictEqual({ name: "user", pass: "100%off" });
  });
});
