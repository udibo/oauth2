import { assertEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

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
    assertEquals(resolve(undefined), "__Host-oauth2_session");
    assertEquals(resolve({ secure: false }), "oauth2_session");
    assertEquals(resolve({ path: "/app" }), "oauth2_session");
    assertEquals(resolve({ domain: "example.com" }), "oauth2_session");
  });

  it("keeps an explicit name the attributes satisfy", () => {
    assertEquals(resolve({}, "__Host-sess"), "__Host-sess");
    assertEquals(resolve({ path: "/app" }, "__Secure-sess"), "__Secure-sess");
    assertEquals(resolve({ secure: false }, "sess"), "sess");
  });

  it("refuses a prefixed name the attributes contradict", () => {
    assertThrows(
      () => resolve({ secure: false }, "__Host-sess"),
      Error,
      "cookie.secure is false",
    );
    assertThrows(
      () => resolve({ domain: "example.com" }, "__host-sess"),
      Error,
      'cookie.domain is "example.com"',
    );
    assertThrows(
      () => resolve({ secure: false }, "__Secure-sess"),
      Error,
      '"__Secure-" prefix',
    );
  });

  it("refuses SameSite=None without Secure, whatever the cookie is named", () => {
    for (const name of [undefined, "sess", "__Host-sess"]) {
      const error = assertThrows(
        () => resolve({ secure: false, sameSite: "None" }, name),
        Error,
      );
      assertEquals(
        error.message.includes('cookie.sameSite is "None"'),
        true,
        `expected the SameSite rule to be reported for name ${name}`,
      );
      assertEquals(error.message.includes(CONSEQUENCE), true);
    }
  });

  it("matches SameSite=None case-insensitively, as browsers do", () => {
    assertThrows(
      () => resolve({ secure: false, sameSite: "none" }),
      Error,
      'cookie.sameSite is "None"',
    );
  });

  it("allows SameSite=None on a Secure cookie and SameSite=Lax on an insecure one", () => {
    assertEquals(
      resolve({ sameSite: "None" }),
      "__Host-oauth2_session",
    );
    assertEquals(
      resolve({ secure: false, sameSite: "Lax" }),
      "oauth2_session",
    );
    assertEquals(
      resolve({ secure: false, sameSite: "Strict" }),
      "oauth2_session",
    );
  });
});

describe("resolvePrefixConstrainedAttributes", () => {
  it("defaults to a Secure, host-bound, root-path cookie with no SameSite of its own", () => {
    assertEquals(resolvePrefixConstrainedAttributes(undefined), {
      secure: true,
      path: "/",
      domain: undefined,
      sameSite: undefined,
    });
  });

  it("treats an empty domain as host-bound", () => {
    assertEquals(
      resolvePrefixConstrainedAttributes({ domain: "" }).domain,
      undefined,
    );
  });
});
