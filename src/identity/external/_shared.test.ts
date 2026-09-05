import {
  assert,
  assertEquals,
  assertFalse,
  assertStringIncludes,
  assertThrows,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { FakeTime } from "@std/testing/time";

import { InvalidGrantError, OAuth2Error } from "../../errors.ts";
import {
  assertIdTokenClaims,
  describeError,
  ID_TOKEN_EXPIRY_LEEWAY_SECONDS,
  type IdTokenClaimsInput,
  PROVIDER_TEXT_MAX_LENGTH,
  readErrorBody,
  sanitizeProviderText,
  stripTrailingSlash,
} from "./_shared.ts";
import { ExternalAuthError } from "./errors.ts";

const NOW_MS = 1_700_000_000_000;
const NOW_SECONDS = NOW_MS / 1000;
const issuer = "https://sso.example";
const clientId = "web-app";

function check(overrides: Partial<IdTokenClaimsInput> = {}): void {
  const { claims, ...rest } = overrides;
  assertIdTokenClaims({
    provider: "test",
    issuer,
    clientId,
    ...rest,
    claims: {
      iss: issuer,
      aud: clientId,
      sub: "user-1",
      exp: NOW_SECONDS + 600,
      ...claims,
    },
  });
}

function rejects(overrides: Partial<IdTokenClaimsInput>): ExternalAuthError {
  return assertThrows(() => check(overrides), ExternalAuthError);
}

describe("describeError", () => {
  it("uses an Error's message", () => {
    assertEquals(describeError(new TypeError("network down")), "network down");
  });

  it("stringifies a non-Error throw", () => {
    assertEquals(describeError("boom"), "boom");
    assertEquals(describeError(undefined), "undefined");
  });

  it("renders an OAuth2 error as code plus description", () => {
    const error = new InvalidGrantError({
      extensions: {
        error: "invalid_grant",
        error_description: "code expired",
      },
    });
    assertEquals(describeError(error), "invalid_grant: code expired");
  });

  it("falls back to an OAuth2 error's message when it carries no description", () => {
    assertEquals(
      describeError(new InvalidGrantError("the code was already used")),
      "invalid_grant: the code was already used",
    );
  });

  it("bounds and flattens a hostile OAuth2 error_description", () => {
    const error = new OAuth2Error({
      extensions: {
        error: "invalid_grant",
        error_description: `\r\n\u001b[31mFORGED audit line\u0000` +
          "d".repeat(50_000),
      },
    });
    const rendered = describeError(error);
    assertFalse(rendered.includes("\n"), "must stay single-line");
    assertFalse(rendered.includes("\r"), "must stay single-line");
    assertFalse(rendered.includes("\u001b"), "ANSI must not survive");
    assert(
      rendered.length <= 2 * PROVIDER_TEXT_MAX_LENGTH + 2,
      `must stay bounded, got ${rendered.length}`,
    );
  });

  it("bounds a hostile non-OAuth2 error message", () => {
    const rendered = describeError(
      new TypeError(`boom\nforged` + "m".repeat(50_000)),
    );
    assertFalse(rendered.includes("\n"));
    assertEquals(rendered.length, PROVIDER_TEXT_MAX_LENGTH);
  });

  it("renders the code alone when the description repeats it", () => {
    const error = new OAuth2Error({
      extensions: { error: "server_error", error_description: "server_error" },
    });
    assertEquals(describeError(error), "server_error");
  });
});

describe("readErrorBody", () => {
  it("returns the trimmed body as a suffix", async () => {
    const body = await readErrorBody(new Response("  bad client  "));
    assertEquals(body, ": bad client");
  });

  it("returns an empty string for an empty or blank body", async () => {
    assertEquals(await readErrorBody(new Response("")), "");
    assertEquals(await readErrorBody(new Response("   \n ")), "");
  });

  it("truncates a long body to 200 characters", async () => {
    const suffix = await readErrorBody(new Response("x".repeat(500)));
    assertEquals(suffix, `: ${"x".repeat(200)}`);
  });

  it("returns an empty string when the body cannot be read", async () => {
    const res = new Response("already read");
    await res.text();
    assertEquals(await readErrorBody(res), "");
  });
});

describe("stripTrailingSlash", () => {
  it("drops a single trailing slash", () => {
    assertEquals(stripTrailingSlash("https://x.example/"), "https://x.example");
  });

  it("leaves a value without a trailing slash untouched", () => {
    assertEquals(stripTrailingSlash("https://x.example"), "https://x.example");
    assertEquals(stripTrailingSlash(""), "");
  });

  it("drops only the last slash", () => {
    assertEquals(
      stripTrailingSlash("https://x.example//"),
      "https://x.example/",
    );
  });
});

describe("assertIdTokenClaims", () => {
  it("accepts a well-formed token", () => {
    using _time = new FakeTime(NOW_MS);
    check();
  });

  it("rejects an iss that is not the expected issuer", () => {
    using _time = new FakeTime(NOW_MS);
    const error = rejects({ claims: { iss: "https://evil.example" } });
    assertEquals(error.code, "provider_error");
    assertEquals(error.provider, "test");
    assertStringIncludes(error.message, `"iss"`);
    assertStringIncludes(error.message, "https://evil.example");
    assertStringIncludes(error.message, issuer);
  });

  it("rejects an aud that does not contain the client id", () => {
    using _time = new FakeTime(NOW_MS);
    const error = rejects({ claims: { aud: "another-client" } });
    assertEquals(error.code, "provider_error");
    assertStringIncludes(error.message, `"aud"`);
  });

  it("accepts an aud array that contains the client id", () => {
    using _time = new FakeTime(NOW_MS);
    check({ claims: { aud: [clientId], azp: clientId } });
  });

  it("rejects an aud array that omits the client id", () => {
    using _time = new FakeTime(NOW_MS);
    const error = rejects({ claims: { aud: ["a", "b"], azp: clientId } });
    assertStringIncludes(error.message, `"aud"`);
  });

  describe("azp", () => {
    it("accepts a single-audience token with no azp claim", () => {
      using _time = new FakeTime(NOW_MS);
      check({ claims: { aud: clientId } });
      check({ claims: { aud: [clientId] } });
    });

    it("accepts an azp claim equal to the client id", () => {
      using _time = new FakeTime(NOW_MS);
      check({ claims: { azp: clientId } });
    });

    it("rejects an azp claim naming a different client, even with one audience", () => {
      using _time = new FakeTime(NOW_MS);
      const error = rejects({ claims: { azp: "another-client" } });
      assertEquals(error.code, "provider_error");
      assertStringIncludes(error.message, `"azp"`);
      assertStringIncludes(error.message, "another-client");
    });

    it("rejects multiple audiences without an azp claim", () => {
      using _time = new FakeTime(NOW_MS);
      const error = rejects({ claims: { aud: [clientId, "other"] } });
      assertStringIncludes(error.message, `"azp"`);
    });

    it("accepts multiple audiences whose azp is the client id", () => {
      using _time = new FakeTime(NOW_MS);
      check({ claims: { aud: [clientId, "other"], azp: clientId } });
    });

    it("applies the conditional check when no policy is given", () => {
      using _time = new FakeTime(NOW_MS);
      const error = assertThrows(
        () =>
          assertIdTokenClaims({
            provider: "test",
            issuer,
            clientId,
            claims: {
              iss: issuer,
              aud: clientId,
              azp: "another-client",
              exp: NOW_SECONDS + 600,
            },
          }),
        ExternalAuthError,
      );
      assertStringIncludes(error.message, `"azp"`);
    });

    it('skips the check entirely under the "ignore" policy', () => {
      using _time = new FakeTime(NOW_MS);
      check({ azp: "ignore", claims: { azp: "another-client" } });
      check({ azp: "ignore", claims: { aud: [clientId, "other"] } });
    });
  });

  describe("exp", () => {
    it("rejects a token with no exp claim", () => {
      using _time = new FakeTime(NOW_MS);
      const error = rejects({ claims: { exp: undefined } });
      assertEquals(error.code, "provider_error");
      assertStringIncludes(error.message, "expired");
    });

    it("rejects a non-numeric exp claim", () => {
      using _time = new FakeTime(NOW_MS);
      const error = rejects({ claims: { exp: `${NOW_SECONDS + 600}` } });
      assertStringIncludes(error.message, "expired");
    });

    it("accepts a token expired by exactly the leeway", () => {
      using _time = new FakeTime(NOW_MS);
      check({ claims: { exp: NOW_SECONDS - ID_TOKEN_EXPIRY_LEEWAY_SECONDS } });
    });

    it("rejects a token expired one second past the leeway", () => {
      using _time = new FakeTime(NOW_MS);
      const error = rejects({
        claims: { exp: NOW_SECONDS - ID_TOKEN_EXPIRY_LEEWAY_SECONDS - 1 },
      });
      assertStringIncludes(error.message, "expired");
    });

    it("honors a caller-supplied leeway", () => {
      using _time = new FakeTime(NOW_MS);
      check({ leewaySeconds: 0, claims: { exp: NOW_SECONDS } });
      const error = rejects({
        leewaySeconds: 0,
        claims: { exp: NOW_SECONDS - 1 },
      });
      assertStringIncludes(error.message, "expired");
    });
  });

  describe("nonce", () => {
    it("accepts a matching nonce", () => {
      using _time = new FakeTime(NOW_MS);
      check({ expectedNonce: "n-1", claims: { nonce: "n-1" } });
    });

    it("rejects a mismatched nonce with the nonce_mismatch code", () => {
      using _time = new FakeTime(NOW_MS);
      const error = rejects({
        expectedNonce: "n-1",
        claims: { nonce: "n-2" },
      });
      assertEquals(error.code, "nonce_mismatch");
    });

    it("rejects a missing or non-string nonce when one was sent", () => {
      using _time = new FakeTime(NOW_MS);
      assertEquals(rejects({ expectedNonce: "n-1" }).code, "nonce_mismatch");
      assertEquals(
        rejects({ expectedNonce: "n-1", claims: { nonce: 42 } }).code,
        "nonce_mismatch",
      );
    });

    it("ignores the nonce claim when none was sent", () => {
      using _time = new FakeTime(NOW_MS);
      check({ claims: { nonce: "unexpected" } });
    });
  });
});

describe("sanitizeProviderText", () => {
  it("caps at the echo limit", () => {
    assertEquals(
      sanitizeProviderText("y".repeat(5_000)).length,
      PROVIDER_TEXT_MAX_LENGTH,
    );
  });

  it("repairs a surrogate pair the cap would split", () => {
    const sanitized = sanitizeProviderText("\u{1F600}".repeat(5_000));
    assert(sanitized.isWellFormed(), "must not end in a lone surrogate");
  });

  it("flattens control characters to spaces", () => {
    assertEquals(sanitizeProviderText("a\r\n\u001b[31mb\u0000c"), "a [31mb c");
  });
});
