import { describe, expect, it } from "vitest";
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
    expect(err.code).toStrictEqual("rate_limited");
    expect(err.retryAfterMs).toStrictEqual(5000);
    expect(err.name).toStrictEqual("IdentityError");
    expect(isIdentityError(err)).toStrictEqual(true);
    expect(isIdentityError(new Error("x"))).toStrictEqual(false);
  });

  it("maps codes to conventional statuses", () => {
    expect(identityErrorStatus("invalid_credentials")).toStrictEqual(401);
    expect(identityErrorStatus("invalid_token")).toStrictEqual(400);
    expect(identityErrorStatus("rate_limited")).toStrictEqual(429);
    expect(identityErrorStatus("weak_password")).toStrictEqual(422);
    expect(identityErrorStatus("identifier_taken")).toStrictEqual(409);
    expect(identityErrorStatus("email_not_verified")).toStrictEqual(403);
    expect(identityErrorStatus("mfa_not_enrolled")).toStrictEqual(409);
    expect(identityErrorStatus("mfa_already_enrolled")).toStrictEqual(409);
  });

  it("carries a captcha_failed code that maps to 403", () => {
    const err = new IdentityError("captcha_failed");
    expect(err.code).toStrictEqual("captcha_failed");
    expect(err.message).toStrictEqual("captcha_failed");
    expect(identityErrorStatus("captcha_failed")).toStrictEqual(403);
  });

  it("carries a forbidden_origin code that maps to 403", () => {
    const err = new IdentityError("forbidden_origin");
    expect(err.code).toStrictEqual("forbidden_origin");
    expect(err.message).toStrictEqual("forbidden_origin");
    expect(identityErrorStatus("forbidden_origin")).toStrictEqual(403);
  });
});
