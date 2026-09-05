import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  buildResetUrl,
  buildSignInUrl,
  buildTokenUrl,
  buildVerificationUrl,
} from "./delivery.ts";

describe("URL builders", () => {
  it("embeds the token as a query param on the given path", () => {
    assertEquals(
      buildTokenUrl("https://app.example", "/reset-password", "tok123"),
      "https://app.example/reset-password?token=tok123",
    );
  });

  it("supports a custom param name and an origin+prefix base", () => {
    assertEquals(
      buildTokenUrl("https://app.example/app/", "verify", "t", "code"),
      "https://app.example/app/verify?code=t",
    );
  });

  it("URL-encodes a token with special characters", () => {
    const url = new URL(buildResetUrl("https://app.example", "a/b+c=d"));
    assertEquals(url.searchParams.get("token"), "a/b+c=d");
  });

  it("buildSignInUrl defaults to /signin-link", () => {
    assertEquals(
      buildSignInUrl("https://app.example", "t"),
      "https://app.example/signin-link?token=t",
    );
  });

  it("buildVerificationUrl / buildResetUrl use sensible default paths", () => {
    assertEquals(
      buildVerificationUrl("https://app.example", "t"),
      "https://app.example/verify-email?token=t",
    );
    assertEquals(
      buildResetUrl("https://app.example", "t"),
      "https://app.example/reset-password?token=t",
    );
  });
});
