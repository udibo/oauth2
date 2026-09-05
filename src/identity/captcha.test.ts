import { assert, assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  type CaptchaProvider,
  type CaptchaVerifyContext,
  verifyCaptcha,
} from "./captcha.ts";

function recordingProvider(
  result: { success: boolean; score?: number } | Error,
): {
  provider: CaptchaProvider;
  calls: { token: string; context?: CaptchaVerifyContext }[];
} {
  const calls: { token: string; context?: CaptchaVerifyContext }[] = [];
  const provider: CaptchaProvider = {
    verify(token, context) {
      calls.push({ token, context });
      if (result instanceof Error) return Promise.reject(result);
      return Promise.resolve(result);
    },
  };
  return { provider, calls };
}

describe("verifyCaptcha", () => {
  it("passes unchallenged when no provider is configured", async () => {
    const outcome = await verifyCaptcha({
      provider: undefined,
      token: "anything",
    });
    assertEquals(outcome.decision, "pass");
    assertEquals(outcome.challenged, false);
    assertEquals(outcome.degraded, false);
  });

  it("hands the token and context to the provider on a pass", async () => {
    const { provider, calls } = recordingProvider({
      success: true,
      score: 0.9,
    });
    const outcome = await verifyCaptcha({
      provider,
      token: "solved-token",
      context: { ip: "203.0.113.7", action: "signin" },
    });
    assertEquals(outcome.decision, "pass");
    assertEquals(outcome.challenged, true);
    assertEquals(outcome.degraded, false);
    assertEquals(outcome.score, 0.9);
    assertEquals(calls.length, 1);
    assertEquals(calls[0].token, "solved-token");
    assertEquals(calls[0].context, { ip: "203.0.113.7", action: "signin" });
  });

  it("fails a token the provider rejects", async () => {
    const { provider, calls } = recordingProvider({ success: false });
    const outcome = await verifyCaptcha({ provider, token: "forged" });
    assertEquals(outcome.decision, "fail");
    assertEquals(outcome.challenged, true);
    assertEquals(outcome.degraded, false);
    assertEquals(calls.length, 1);
  });

  it("fails a missing token without calling the provider", async () => {
    const { provider, calls } = recordingProvider({ success: true });
    const outcome = await verifyCaptcha({ provider, token: null });
    assertEquals(outcome.decision, "fail");
    assertEquals(outcome.challenged, true);
    assertEquals(calls.length, 0);
  });

  it("fails an empty-string token without calling the provider", async () => {
    const { provider, calls } = recordingProvider({ success: true });
    const outcome = await verifyCaptcha({ provider, token: "" });
    assertEquals(outcome.decision, "fail");
    assertEquals(calls.length, 0);
  });

  it("fails open on a provider outage by default", async () => {
    const { provider } = recordingProvider(new Error("network down"));
    const outcome = await verifyCaptcha({ provider, token: "token" });
    assertEquals(outcome.decision, "pass");
    assertEquals(outcome.challenged, true);
    assert(outcome.degraded, "an outage pass must be flagged degraded");
  });

  it("fails closed on a provider outage when configured", async () => {
    const { provider } = recordingProvider(new Error("network down"));
    const outcome = await verifyCaptcha({
      provider,
      token: "token",
      failOpen: false,
    });
    assertEquals(outcome.decision, "fail");
    assertEquals(outcome.challenged, true);
    assert(
      outcome.degraded,
      "a fail-closed outage is still a degraded evaluation",
    );
  });
});
