import { describe, expect, it } from "vitest";
import { thrown } from "../../../_test_assert.ts";
import {
  type PrefixConstrainedOptions,
  resolveCookieName,
  resolvePrefixConstrainedAttributes,
} from "./cookie-prefix.ts";

const CONSEQUENCE = "the session would silently never persist";

function resolve(
  options: PrefixConstrainedOptions | undefined,
  name?: string,
): string {
  return resolveCookieName({
    name,
    base: "oauth2_session",
    attributes: resolvePrefixConstrainedAttributes(options),
    consequence: CONSEQUENCE,
  });
}

describe("resolveCookieName", () => {
  it("prefixes the default name with __Host- only when the attributes allow it", () => {
    expect(resolve(undefined)).toStrictEqual("__Host-oauth2_session");
    expect(resolve({ secure: false })).toStrictEqual("oauth2_session");
    expect(resolve({ path: "/app" })).toStrictEqual("oauth2_session");
    expect(resolve({ domain: "example.com" })).toStrictEqual("oauth2_session");
  });

  it("keeps an explicit name the attributes satisfy", () => {
    expect(resolve({}, "__Host-sess")).toStrictEqual("__Host-sess");
    expect(resolve({ path: "/app" }, "__Secure-sess")).toStrictEqual(
      "__Secure-sess",
    );
    expect(resolve({ secure: false }, "sess")).toStrictEqual("sess");
  });

  it("refuses a prefixed name the attributes contradict", () => {
    thrown(
      () => resolve({ secure: false }, "__Host-sess"),
      Error,
      "cookie.secure is false",
    );
    thrown(
      () => resolve({ domain: "example.com" }, "__host-sess"),
      Error,
      'cookie.domain is "example.com"',
    );
    thrown(
      () => resolve({ secure: false }, "__Secure-sess"),
      Error,
      '"__Secure-" prefix',
    );
  });

  it("refuses SameSite=None without Secure, whatever the cookie is named", () => {
    for (const name of [undefined, "sess", "__Host-sess"]) {
      const error = thrown(
        () => resolve({ secure: false, sameSite: "None" }, name),
        Error,
      );
      expect(
        error.message.includes('cookie.sameSite is "None"'),
        `expected the SameSite rule to be reported for name ${name}`,
      ).toStrictEqual(true);
      expect(error.message.includes(CONSEQUENCE)).toStrictEqual(true);
    }
  });

  it("matches SameSite=None case-insensitively, as browsers do", () => {
    thrown(
      () => resolve({ secure: false, sameSite: "none" }),
      Error,
      'cookie.sameSite is "None"',
    );
  });

  it("allows SameSite=None on a Secure cookie and SameSite=Lax on an insecure one", () => {
    expect(resolve({ sameSite: "None" })).toStrictEqual(
      "__Host-oauth2_session",
    );
    expect(resolve({ secure: false, sameSite: "Lax" })).toStrictEqual(
      "oauth2_session",
    );
    expect(resolve({ secure: false, sameSite: "Strict" })).toStrictEqual(
      "oauth2_session",
    );
  });
});

describe("resolvePrefixConstrainedAttributes", () => {
  it("defaults to a Secure, host-bound, root-path cookie with no SameSite of its own", () => {
    expect(resolvePrefixConstrainedAttributes(undefined)).toStrictEqual({
      secure: true,
      path: "/",
      domain: undefined,
      sameSite: undefined,
    });
  });

  it("treats an empty domain as host-bound", () => {
    expect(
      resolvePrefixConstrainedAttributes({ domain: "" }).domain,
    ).toStrictEqual(undefined);
  });
});
