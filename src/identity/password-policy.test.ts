import { describe, expect, it } from "vitest";
import { rejection } from "../_test_assert.ts";
import {
  assertPasswordPolicy,
  checkPasswordPolicy,
} from "./password-policy.ts";
import { IdentityError } from "./errors.ts";

describe("checkPasswordPolicy", () => {
  it("enforces the default length floor", async () => {
    expect((await checkPasswordPolicy("short")).ok).toStrictEqual(false);
    expect((await checkPasswordPolicy("longenough")).ok).toStrictEqual(true);
  });

  it("enforces min/max and runs custom validators, collecting issues", async () => {
    const result = await checkPasswordPolicy("abc", {
      minLength: 10,
      validators: [(p) => (/\d/.test(p) ? undefined : "Needs a digit.")],
    });
    expect(result.ok).toStrictEqual(false);
    expect(result.issues.length).toStrictEqual(2);

    const max = await checkPasswordPolicy("x".repeat(5), { maxLength: 4 });
    expect(max.ok).toStrictEqual(false);
  });

  it("awaits async validators", async () => {
    const result = await checkPasswordPolicy("longenough", {
      validators: [
        (p) => Promise.resolve(p === "longenough" ? "Known." : undefined),
      ],
    });
    expect(result.ok).toStrictEqual(false);
    expect(result.issues).toStrictEqual(["Known."]);
  });

  it("fails closed on a non-string password instead of skipping the length checks", async () => {
    const lengthless = [
      12345678901234,
      { length: 12 },
      ["x".repeat(20)],
      true,
      null,
    ];
    for (const password of lengthless) {
      const result = await checkPasswordPolicy(password as unknown as string);
      expect(result.ok, `${JSON.stringify(password)} must fail`).toStrictEqual(
        false,
      );
    }
  });

  it("does not run validators on a non-string password", async () => {
    let calls = 0;
    const result = await checkPasswordPolicy(9 as unknown as string, {
      validators: [
        () => {
          calls++;
          return undefined;
        },
      ],
    });
    expect(result.ok).toStrictEqual(false);
    expect(calls).toStrictEqual(0);
  });
});

describe("assertPasswordPolicy", () => {
  it("throws IdentityError('weak_password') on failure, passes otherwise", async () => {
    const err = await rejection(
      () => assertPasswordPolicy("x", { minLength: 8 }),
      IdentityError,
    );
    expect((err as IdentityError).code).toStrictEqual("weak_password");
    await assertPasswordPolicy("longenough1");
  });

  it("rejects a non-string password as weak_password", async () => {
    const err = await rejection(
      () => assertPasswordPolicy(12345678901234 as unknown as string),
      IdentityError,
    );
    expect((err as IdentityError).code).toStrictEqual("weak_password");
  });

  it("traps a throwing validator as weak_password instead of a raw error", async () => {
    const err = await rejection(
      () =>
        assertPasswordPolicy("longenough1", {
          validators: [
            () => {
              throw new Error("breach service exploded");
            },
          ],
        }),
      IdentityError,
    );
    expect((err as IdentityError).code).toStrictEqual("weak_password");
  });

  it("preserves an IdentityError a validator throws itself", async () => {
    const err = await rejection(
      () =>
        assertPasswordPolicy("longenough1", {
          validators: [
            () => {
              throw new IdentityError("rate_limited", "slow down");
            },
          ],
        }),
      IdentityError,
    );
    expect((err as IdentityError).code).toStrictEqual("rate_limited");
  });
});
