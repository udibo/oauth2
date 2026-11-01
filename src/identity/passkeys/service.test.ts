import { assert, describe, expect, it } from "vitest";
import { FakeTime } from "../../_test_fake-time.ts";
import { rejection, thrown } from "../../_test_assert.ts";
import { TestPasskeyAuthenticator } from "../../testing/passkey-authenticator.ts";
import { IdentityError } from "../errors.ts";
import type { IdentityEvent } from "../events.ts";
import { MemoryRateLimitStore, RateLimiter } from "../rate-limit.ts";
import {
  MemoryPasskeyChallengeStore,
  MemoryPasskeyStore,
  PASSKEY_AMR,
  type PasskeyRelyingParty,
  PasskeyService,
  type PasskeyServiceOptions,
} from "./service.ts";

const ORIGIN = "https://login.example.com";
const RP: PasskeyRelyingParty = {
  id: "login.example.com",
  name: "Example",
  origins: [ORIGIN],
};
const ADA = { id: "user-ada", name: "ada@example.com", displayName: "Ada" };
const BOB = { id: "user-bob", name: "bob@example.com", displayName: "Bob" };

function setup(options: Partial<PasskeyServiceOptions> = {}) {
  const events: IdentityEvent[] = [];
  const store = new MemoryPasskeyStore();
  const passkeys = new PasskeyService({
    store,
    challenges: new MemoryPasskeyChallengeStore(),
    onEvent: (event) => {
      events.push(event);
    },
    ...options,
  });
  return { passkeys, store, events };
}

async function register(
  passkeys: PasskeyService,
  authenticator: TestPasskeyAuthenticator,
  user = ADA,
  relyingParty = RP,
) {
  const { ceremonyId, options } = await passkeys.startRegistration({
    relyingParty,
    user,
  });
  const result = await passkeys.finishRegistration({
    relyingParty,
    ceremonyId,
    userId: user.id,
    response: await authenticator.register(options),
    name: "Laptop",
  });
  assert(result.registered, "registration should succeed");
  return result.passkey;
}

async function signIn(
  passkeys: PasskeyService,
  authenticator: TestPasskeyAuthenticator,
  overrides: Parameters<TestPasskeyAuthenticator["authenticate"]>[1] = {},
  userId?: string,
) {
  const { ceremonyId, options } = await passkeys.startAuthentication({
    relyingParty: RP,
    ...(userId !== undefined ? { userId } : {}),
  });
  return await passkeys.finishAuthentication({
    relyingParty: RP,
    ceremonyId,
    response: await authenticator.authenticate(options, overrides),
  });
}

describe("PasskeyService registration", () => {
  it("asks for a discoverable credential without attestation and stores it", async () => {
    const { passkeys, store, events } = setup();
    const { ceremonyId, options } = await passkeys.startRegistration({
      relyingParty: RP,
      user: ADA,
    });
    expect(options.attestation).toBe("none");
    expect(options.rp).toStrictEqual({ id: RP.id, name: RP.name });
    expect(options.authenticatorSelection?.residentKey).toBe("required");
    expect(options.authenticatorSelection?.userVerification).toBe("preferred");
    expect(options.pubKeyCredParams.map((param) => param.alg)).toStrictEqual([
      -8, -7, -257,
    ]);
    expect(options.user.name).toBe(ADA.name);
    expect(options.user.displayName).toBe("Ada");

    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    const result = await passkeys.finishRegistration({
      relyingParty: RP,
      ceremonyId,
      userId: ADA.id,
      response: await authenticator.register(options),
    });
    assert(result.registered);
    expect(result.userVerified).toBe(true);
    expect(result.passkey).toMatchObject({
      userId: ADA.id,
      rpId: RP.id,
      signCount: 0,
      multiDevice: true,
      backedUp: true,
      name: "Passkey",
      lastUsedAt: null,
    });
    expect(await store.findPasskey(result.passkey.credentialId)).toStrictEqual(
      result.passkey,
    );
    expect(events).toContainEqual({
      type: "passkey.registered",
      userId: ADA.id,
      credentialId: result.passkey.credentialId,
      multiDevice: true,
    });
  });

  it("records a security key as bound to one device", async () => {
    const { passkeys } = setup();
    const key = new TestPasskeyAuthenticator({ origin: ORIGIN, synced: false });
    const passkey = await register(passkeys, key);
    expect(passkey.multiDevice).toBe(false);
    expect(passkey.backedUp).toBe(false);
  });

  it("excludes the user's existing passkeys under the same relying party", async () => {
    const { passkeys } = setup();
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    const first = await register(passkeys, authenticator);
    await register(
      passkeys,
      new TestPasskeyAuthenticator({ origin: "https://other.example.com" }),
      ADA,
      {
        id: "other.example.com",
        name: "Other",
        origins: ["https://other.example.com"],
      },
    );
    const { options } = await passkeys.startRegistration({
      relyingParty: RP,
      user: ADA,
    });
    expect(
      options.excludeCredentials?.map((credential) => credential.id),
    ).toStrictEqual([first.credentialId]);
  });

  it("spends the challenge so a ceremony cannot be finished twice", async () => {
    const { passkeys } = setup();
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    const { ceremonyId, options } = await passkeys.startRegistration({
      relyingParty: RP,
      user: ADA,
    });
    const response = await authenticator.register(options);
    const first = await passkeys.finishRegistration({
      relyingParty: RP,
      ceremonyId,
      userId: ADA.id,
      response,
    });
    expect(first.registered).toBe(true);
    expect(
      await passkeys.finishRegistration({
        relyingParty: RP,
        ceremonyId,
        userId: ADA.id,
        response,
      }),
    ).toStrictEqual({ registered: false, reason: "expired_challenge" });
  });

  it("refuses a ceremony finished for a different user", async () => {
    const { passkeys, events } = setup();
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    const { ceremonyId, options } = await passkeys.startRegistration({
      relyingParty: RP,
      user: ADA,
    });
    const result = await passkeys.finishRegistration({
      relyingParty: RP,
      ceremonyId,
      userId: BOB.id,
      response: await authenticator.register(options),
    });
    expect(result).toStrictEqual({ registered: false, reason: "invalid" });
    expect(events).toContainEqual({
      type: "passkey.registration.failed",
      userId: BOB.id,
      reason: "invalid",
    });
  });

  it("refuses a response created on another origin", async () => {
    const { passkeys } = setup();
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    const { ceremonyId, options } = await passkeys.startRegistration({
      relyingParty: RP,
      user: ADA,
    });
    const result = await passkeys.finishRegistration({
      relyingParty: RP,
      ceremonyId,
      userId: ADA.id,
      response: await authenticator.register(options, {
        origin: "https://login.examp1e.com",
      }),
    });
    expect(result).toStrictEqual({ registered: false, reason: "invalid" });
  });

  it("refuses a challenge that has expired", async () => {
    using time = new FakeTime("2026-11-01T00:00:00.000Z");
    const { passkeys } = setup({ challengeTtlMs: 60_000 });
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    const { ceremonyId, options } = await passkeys.startRegistration({
      relyingParty: RP,
      user: ADA,
    });
    time.tick(60_000);
    const result = await passkeys.finishRegistration({
      relyingParty: RP,
      ceremonyId,
      userId: ADA.id,
      response: await authenticator.register(options),
    });
    expect(result).toStrictEqual({
      registered: false,
      reason: "expired_challenge",
    });
  });

  it("stops at the per-user limit before and after the browser step", async () => {
    const { passkeys } = setup({ maxPasskeysPerUser: 1 });
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    const pending = await passkeys.startRegistration({
      relyingParty: RP,
      user: ADA,
    });
    await register(passkeys, authenticator);

    const error = await rejection(
      () => passkeys.startRegistration({ relyingParty: RP, user: ADA }),
      IdentityError,
    );
    expect(error.code).toBe("passkey_limit_reached");

    const late = await passkeys.finishRegistration({
      relyingParty: RP,
      ceremonyId: pending.ceremonyId,
      userId: ADA.id,
      response: await authenticator.register(pending.options),
    });
    expect(late).toStrictEqual({ registered: false, reason: "limit_reached" });
  });

  it("refuses an authentication ceremony's challenge", async () => {
    const { passkeys } = setup();
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    const registration = await passkeys.startRegistration({
      relyingParty: RP,
      user: ADA,
    });
    const authentication = await passkeys.startAuthentication({
      relyingParty: RP,
    });
    const result = await passkeys.finishRegistration({
      relyingParty: RP,
      ceremonyId: authentication.ceremonyId,
      userId: ADA.id,
      response: await authenticator.register(registration.options),
    });
    expect(result).toStrictEqual({ registered: false, reason: "invalid" });
  });

  it("rejects user ids that cannot be a user handle", async () => {
    const { passkeys } = setup();
    const error = await rejection(
      () =>
        passkeys.startRegistration({
          relyingParty: RP,
          user: { id: "x".repeat(65), name: "long" },
        }),
      TypeError,
    );
    expect(error.message).toContain("64");
  });
});

describe("PasskeyService authentication", () => {
  it("signs in without an identifier and reports user verification", async () => {
    const { passkeys, events } = setup();
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    const passkey = await register(passkeys, authenticator);

    const { options } = await passkeys.startAuthentication({
      relyingParty: RP,
    });
    expect(options.allowCredentials).toBe(undefined);
    expect(options.userVerification).toBe("preferred");
    expect(options.rpId).toBe(RP.id);

    const result = await signIn(passkeys, authenticator);
    assert(result.valid);
    expect(result.userId).toBe(ADA.id);
    expect(result.userVerified).toBe(true);
    expect(result.passkey.credentialId).toBe(passkey.credentialId);
    expect(result.passkey.lastUsedAt).toBeInstanceOf(Date);
    expect(events).toContainEqual({
      type: "passkey.verify.succeeded",
      userId: ADA.id,
      credentialId: passkey.credentialId,
      userVerified: true,
    });
  });

  it("reports a passkey used without user verification", async () => {
    const { passkeys } = setup();
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    await register(passkeys, authenticator);
    const result = await signIn(passkeys, authenticator, {
      userVerified: false,
    });
    assert(result.valid);
    expect(result.userVerified).toBe(false);
  });

  it("refuses an assertion made for a lookalike origin", async () => {
    const { passkeys, events } = setup();
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    const passkey = await register(passkeys, authenticator);
    const result = await signIn(passkeys, authenticator, {
      origin: "https://login.examp1e.com",
    });
    expect(result).toStrictEqual({ valid: false, reason: "invalid" });
    expect(events).toContainEqual({
      type: "passkey.verify.failed",
      reason: "invalid",
      credentialId: passkey.credentialId,
      userId: ADA.id,
    });
  });

  it("refuses a passkey registered under another relying party", async () => {
    const { passkeys } = setup();
    const other = { id: "other.example.com", name: "Other", origins: [ORIGIN] };
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    const passkey = await register(passkeys, authenticator, ADA, other);
    const { ceremonyId, options } = await passkeys.startAuthentication({
      relyingParty: RP,
    });
    const response = await authenticator.authenticate(
      { ...options, rpId: other.id },
      { credentialId: passkey.credentialId },
    );
    expect(
      await passkeys.finishAuthentication({
        relyingParty: RP,
        ceremonyId,
        response,
      }),
    ).toStrictEqual({ valid: false, reason: "unknown_passkey" });
  });

  it("refuses an unknown credential", async () => {
    const { passkeys } = setup();
    const stranger = new TestPasskeyAuthenticator({ origin: ORIGIN });
    const { options: registrationOptions } = await passkeys.startRegistration({
      relyingParty: RP,
      user: ADA,
    });
    await stranger.register(registrationOptions);
    expect(await signIn(passkeys, stranger)).toStrictEqual({
      valid: false,
      reason: "unknown_passkey",
    });
  });

  it("spends the challenge so an assertion cannot be replayed", async () => {
    const { passkeys } = setup();
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    await register(passkeys, authenticator);
    const { ceremonyId, options } = await passkeys.startAuthentication({
      relyingParty: RP,
    });
    const response = await authenticator.authenticate(options);
    const first = await passkeys.finishAuthentication({
      relyingParty: RP,
      ceremonyId,
      response,
    });
    expect(first.valid).toBe(true);
    expect(
      await passkeys.finishAuthentication({
        relyingParty: RP,
        ceremonyId,
        response,
      }),
    ).toStrictEqual({ valid: false, reason: "expired_challenge" });
  });

  it("refuses an assertion signed over a different challenge", async () => {
    const { passkeys } = setup();
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    await register(passkeys, authenticator);
    const first = await passkeys.startAuthentication({ relyingParty: RP });
    const second = await passkeys.startAuthentication({ relyingParty: RP });
    const response = await authenticator.authenticate(first.options);
    expect(
      await passkeys.finishAuthentication({
        relyingParty: RP,
        ceremonyId: second.ceremonyId,
        response,
      }),
    ).toStrictEqual({ valid: false, reason: "invalid" });
  });

  it("refuses a registration ceremony's challenge for sign-in", async () => {
    const { passkeys } = setup();
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    await register(passkeys, authenticator);
    const registration = await passkeys.startRegistration({
      relyingParty: RP,
      user: ADA,
    });
    const response = await authenticator.authenticate({
      challenge: registration.options.challenge,
      rpId: RP.id,
    });
    expect(
      await passkeys.finishAuthentication({
        relyingParty: RP,
        ceremonyId: registration.ceremonyId,
        response,
      }),
    ).toStrictEqual({ valid: false, reason: "invalid" });
  });

  it("lists only the bound user's passkeys for a second factor", async () => {
    const { passkeys } = setup();
    const adaKey = new TestPasskeyAuthenticator({ origin: ORIGIN });
    const bobKey = new TestPasskeyAuthenticator({ origin: ORIGIN });
    const adaPasskey = await register(passkeys, adaKey);
    const bobPasskey = await register(passkeys, bobKey, BOB);

    const { ceremonyId, options } = await passkeys.startAuthentication({
      relyingParty: RP,
      userId: ADA.id,
    });
    expect(
      options.allowCredentials?.map((credential) => credential.id),
    ).toStrictEqual([adaPasskey.credentialId]);
    const response = await bobKey.authenticate(options, {
      credentialId: bobPasskey.credentialId,
    });
    expect(
      await passkeys.finishAuthentication({
        relyingParty: RP,
        ceremonyId,
        response,
      }),
    ).toStrictEqual({ valid: false, reason: "invalid" });
  });

  it("refuses a second-factor ceremony for a user with no passkey", async () => {
    const { passkeys } = setup();
    const error = await rejection(
      () => passkeys.startAuthentication({ relyingParty: RP, userId: BOB.id }),
      IdentityError,
    );
    expect(error.code).toBe("passkey_not_registered");
  });

  it("refuses a user handle that does not match the passkey's account", async () => {
    const { passkeys } = setup();
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    await register(passkeys, authenticator);
    const { ceremonyId, options } = await passkeys.startAuthentication({
      relyingParty: RP,
    });
    const response = await authenticator.authenticate(options);
    response.response.userHandle = "dXNlci1ib2I";
    expect(
      await passkeys.finishAuthentication({
        relyingParty: RP,
        ceremonyId,
        response,
      }),
    ).toStrictEqual({ valid: false, reason: "invalid" });
  });

  it("accepts an increasing counter and refuses one that goes backwards", async () => {
    const { passkeys, events } = setup();
    const key = new TestPasskeyAuthenticator({
      origin: ORIGIN,
      synced: false,
      countSignatures: true,
    });
    await register(passkeys, key);
    const used = await signIn(passkeys, key);
    assert(used.valid);
    expect(used.passkey.signCount).toBe(2);

    expect(await signIn(passkeys, key, { signCount: 2 })).toStrictEqual({
      valid: false,
      reason: "sign_count",
    });
    expect(events.at(-1)).toMatchObject({
      type: "passkey.verify.failed",
      reason: "sign_count",
    });
  });

  it("lets only one of two concurrent uses of a counting key through", async () => {
    const { passkeys } = setup();
    const key = new TestPasskeyAuthenticator({
      origin: ORIGIN,
      synced: false,
      countSignatures: true,
    });
    await register(passkeys, key);
    const first = await passkeys.startAuthentication({ relyingParty: RP });
    const second = await passkeys.startAuthentication({ relyingParty: RP });
    const responses = [
      await key.authenticate(first.options, { signCount: 5 }),
      await key.authenticate(second.options, { signCount: 6 }),
    ];
    const results = await Promise.all([
      passkeys.finishAuthentication({
        relyingParty: RP,
        ceremonyId: first.ceremonyId,
        response: responses[0]!,
      }),
      passkeys.finishAuthentication({
        relyingParty: RP,
        ceremonyId: second.ceremonyId,
        response: responses[1]!,
      }),
    ]);
    expect(results.filter((result) => result.valid)).toHaveLength(1);
    expect(results.find((result) => !result.valid)).toStrictEqual({
      valid: false,
      reason: "replayed",
    });
  });

  it("throws rate_limited per user when enforcing", async () => {
    const { passkeys } = setup({
      rateLimiter: new RateLimiter({
        limit: 1,
        windowMs: 60_000,
        store: new MemoryRateLimitStore(),
      }),
    });
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    await register(passkeys, authenticator);
    expect(
      (
        await signIn(
          passkeys,
          authenticator,
          { origin: "https://evil.test" },
          ADA.id,
        )
      ).valid,
    ).toBe(false);
    const error = await rejection(
      () => signIn(passkeys, authenticator, {}, ADA.id),
      IdentityError,
    );
    expect(error.code).toBe("rate_limited");
  });

  it("lets attempts through in log-only protection mode", async () => {
    const { passkeys, events } = setup({
      protectionMode: "log-only",
      rateLimiter: new RateLimiter({
        limit: 1,
        windowMs: 60_000,
        store: new MemoryRateLimitStore(),
      }),
    });
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    await register(passkeys, authenticator);
    await signIn(
      passkeys,
      authenticator,
      { origin: "https://evil.test" },
      ADA.id,
    );
    expect((await signIn(passkeys, authenticator, {}, ADA.id)).valid).toBe(
      true,
    );
    const limited = events.find(
      (event) => event.type === "passkey.verify.rate_limited",
    );
    assert(limited?.type === "passkey.verify.rate_limited");
    expect(limited.enforced).toBe(false);
  });
});

describe("PasskeyService management", () => {
  it("renames with a trimmed, bounded name and removes only the owner's passkey", async () => {
    const { passkeys, events } = setup();
    const authenticator = new TestPasskeyAuthenticator({ origin: ORIGIN });
    const passkey = await register(passkeys, authenticator);

    expect(
      await passkeys.renamePasskey(BOB.id, passkey.credentialId, "x"),
    ).toBe(false);
    expect(
      await passkeys.renamePasskey(
        ADA.id,
        passkey.credentialId,
        `  ${"p".repeat(80)}  `,
      ),
    ).toBe(true);
    expect((await passkeys.listPasskeys(ADA.id))[0]?.name).toBe("p".repeat(64));
    await passkeys.renamePasskey(ADA.id, passkey.credentialId, "   ");
    expect((await passkeys.listPasskeys(ADA.id))[0]?.name).toBe("Passkey");

    expect(await passkeys.removePasskey(BOB.id, passkey.credentialId)).toBe(
      false,
    );
    expect(await passkeys.removePasskey(ADA.id, passkey.credentialId)).toBe(
      true,
    );
    expect(await passkeys.listPasskeys(ADA.id)).toStrictEqual([]);
    expect(
      events.filter(
        (event) =>
          event.type === "passkey.renamed" || event.type === "passkey.removed",
      ),
    ).toStrictEqual([
      {
        type: "passkey.renamed",
        userId: ADA.id,
        credentialId: passkey.credentialId,
      },
      {
        type: "passkey.renamed",
        userId: ADA.id,
        credentialId: passkey.credentialId,
      },
      {
        type: "passkey.removed",
        userId: ADA.id,
        credentialId: passkey.credentialId,
      },
    ]);
    expect(await signIn(passkeys, authenticator)).toStrictEqual({
      valid: false,
      reason: "unknown_passkey",
    });
  });

  it("rejects unusable configuration at construction", () => {
    const base = {
      store: new MemoryPasskeyStore(),
      challenges: new MemoryPasskeyChallengeStore(),
    };
    thrown(
      () => new PasskeyService({ ...base, maxPasskeysPerUser: 0 }),
      TypeError,
    );
    thrown(
      () => new PasskeyService({ ...base, challengeTtlMs: 1.5 }),
      TypeError,
    );
    expect(new PasskeyService(base).maxPasskeysPerUser).toBe(25);
  });

  it("names the passkey amr value", () => {
    expect(PASSKEY_AMR).toBe("pop");
  });
});
