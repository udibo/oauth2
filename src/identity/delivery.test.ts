import { describe, expect, it } from "vitest";
import {
  buildResetUrl,
  buildSignInUrl,
  buildTokenUrl,
  buildVerificationUrl,
} from "./delivery.ts";

describe("URL builders", () => {
  it("embeds the token as a query param on the given path", () => {
    expect(
      buildTokenUrl("https://app.example", "/reset-password", "tok123"),
    ).toStrictEqual("https://app.example/reset-password?token=tok123");
  });

  it("supports a custom param name and an origin+prefix base", () => {
    expect(
      buildTokenUrl("https://app.example/app/", "verify", "t", "code"),
    ).toStrictEqual("https://app.example/app/verify?code=t");
  });

  it("URL-encodes a token with special characters", () => {
    const url = new URL(buildResetUrl("https://app.example", "a/b+c=d"));
    expect(url.searchParams.get("token")).toStrictEqual("a/b+c=d");
  });

  it("buildSignInUrl defaults to /signin-link", () => {
    expect(buildSignInUrl("https://app.example", "t")).toStrictEqual(
      "https://app.example/signin-link?token=t",
    );
  });

  it("buildVerificationUrl / buildResetUrl use sensible default paths", () => {
    expect(buildVerificationUrl("https://app.example", "t")).toStrictEqual(
      "https://app.example/verify-email?token=t",
    );
    expect(buildResetUrl("https://app.example", "t")).toStrictEqual(
      "https://app.example/reset-password?token=t",
    );
  });
});
