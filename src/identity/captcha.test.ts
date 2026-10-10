import { assert, describe, expect, it } from "vitest";
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
    expect(outcome.decision).toStrictEqual("pass");
    expect(outcome.challenged).toStrictEqual(false);
    expect(outcome.degraded).toStrictEqual(false);
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
    expect(outcome.decision).toStrictEqual("pass");
    expect(outcome.challenged).toStrictEqual(true);
    expect(outcome.degraded).toStrictEqual(false);
    expect(outcome.score).toStrictEqual(0.9);
    expect(calls.length).toStrictEqual(1);
    expect(calls[0].token).toStrictEqual("solved-token");
    expect(calls[0].context).toStrictEqual({
      ip: "203.0.113.7",
      action: "signin",
    });
  });

  it("fails a token the provider rejects", async () => {
    const { provider, calls } = recordingProvider({ success: false });
    const outcome = await verifyCaptcha({ provider, token: "forged" });
    expect(outcome.decision).toStrictEqual("fail");
    expect(outcome.challenged).toStrictEqual(true);
    expect(outcome.degraded).toStrictEqual(false);
    expect(calls.length).toStrictEqual(1);
  });

  it("fails a missing token without calling the provider", async () => {
    const { provider, calls } = recordingProvider({ success: true });
    const outcome = await verifyCaptcha({ provider, token: null });
    expect(outcome.decision).toStrictEqual("fail");
    expect(outcome.challenged).toStrictEqual(true);
    expect(calls.length).toStrictEqual(0);
  });

  it("fails an empty-string token without calling the provider", async () => {
    const { provider, calls } = recordingProvider({ success: true });
    const outcome = await verifyCaptcha({ provider, token: "" });
    expect(outcome.decision).toStrictEqual("fail");
    expect(calls.length).toStrictEqual(0);
  });

  it("fails open on a provider outage by default", async () => {
    const { provider } = recordingProvider(new Error("network down"));
    const outcome = await verifyCaptcha({ provider, token: "token" });
    expect(outcome.decision).toStrictEqual("pass");
    expect(outcome.challenged).toStrictEqual(true);
    assert(outcome.degraded, "an outage pass must be flagged degraded");
  });

  it("fails closed on a provider outage when configured", async () => {
    const { provider } = recordingProvider(new Error("network down"));
    const outcome = await verifyCaptcha({
      provider,
      token: "token",
      failOpen: false,
    });
    expect(outcome.decision).toStrictEqual("fail");
    expect(outcome.challenged).toStrictEqual(true);
    assert(
      outcome.degraded,
      "a fail-closed outage is still a degraded evaluation",
    );
  });
});
