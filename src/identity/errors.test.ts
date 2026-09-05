import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  IdentityError,
  identityErrorStatus,
  isIdentityError,
} from "./errors.ts";

describe("IdentityError", () => {
  it("carries a code and optional retryAfterMs", () => {
    const err = new IdentityError("rate_limited", "slow down", {
      retryAfterMs: 5000,
    });
    assertEquals(err.code, "rate_limited");
    assertEquals(err.retryAfterMs, 5000);
    assertEquals(err.name, "IdentityError");
    assertEquals(isIdentityError(err), true);
    assertEquals(isIdentityError(new Error("x")), false);
  });

  it("maps codes to conventional statuses", () => {
    assertEquals(identityErrorStatus("invalid_credentials"), 401);
    assertEquals(identityErrorStatus("invalid_token"), 400);
    assertEquals(identityErrorStatus("rate_limited"), 429);
    assertEquals(identityErrorStatus("weak_password"), 422);
    assertEquals(identityErrorStatus("identifier_taken"), 409);
    assertEquals(identityErrorStatus("email_not_verified"), 403);
    assertEquals(identityErrorStatus("mfa_not_enrolled"), 409);
    assertEquals(identityErrorStatus("mfa_already_enrolled"), 409);
  });

  it("carries a captcha_failed code that maps to 403", () => {
    const err = new IdentityError("captcha_failed");
    assertEquals(err.code, "captcha_failed");
    assertEquals(err.message, "captcha_failed");
    assertEquals(identityErrorStatus("captcha_failed"), 403);
  });

  it("carries a forbidden_origin code that maps to 403", () => {
    const err = new IdentityError("forbidden_origin");
    assertEquals(err.code, "forbidden_origin");
    assertEquals(err.message, "forbidden_origin");
    assertEquals(identityErrorStatus("forbidden_origin"), 403);
  });
});
