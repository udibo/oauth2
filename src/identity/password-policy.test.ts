import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  assertPasswordPolicy,
  checkPasswordPolicy,
} from "./password-policy.ts";
import { IdentityError } from "./errors.ts";

describe("checkPasswordPolicy", () => {
  it("enforces the default length floor", async () => {
    assertEquals((await checkPasswordPolicy("short")).ok, false);
    assertEquals((await checkPasswordPolicy("longenough")).ok, true);
  });

  it("enforces min/max and runs custom validators, collecting issues", async () => {
    const result = await checkPasswordPolicy("abc", {
      minLength: 10,
      validators: [(p) => (/\d/.test(p) ? undefined : "Needs a digit.")],
    });
    assertEquals(result.ok, false);
    assertEquals(result.issues.length, 2);

    const max = await checkPasswordPolicy("x".repeat(5), { maxLength: 4 });
    assertEquals(max.ok, false);
  });

  it("awaits async validators", async () => {
    const result = await checkPasswordPolicy("longenough", {
      validators: [
        (p) => Promise.resolve(p === "longenough" ? "Known." : undefined),
      ],
    });
    assertEquals(result.ok, false);
    assertEquals(result.issues, ["Known."]);
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
      assertEquals(result.ok, false, `${JSON.stringify(password)} must fail`);
    }
  });

  it("does not run validators on a non-string password", async () => {
    let calls = 0;
    const result = await checkPasswordPolicy(9 as unknown as string, {
      validators: [() => {
        calls++;
        return undefined;
      }],
    });
    assertEquals(result.ok, false);
    assertEquals(calls, 0);
  });
});

describe("assertPasswordPolicy", () => {
  it("throws IdentityError('weak_password') on failure, passes otherwise", async () => {
    const err = await assertRejects(
      () => assertPasswordPolicy("x", { minLength: 8 }),
      IdentityError,
    );
    assertEquals((err as IdentityError).code, "weak_password");
    await assertPasswordPolicy("longenough1");
  });

  it("rejects a non-string password as weak_password", async () => {
    const err = await assertRejects(
      () => assertPasswordPolicy(12345678901234 as unknown as string),
      IdentityError,
    );
    assertEquals((err as IdentityError).code, "weak_password");
  });

  it("traps a throwing validator as weak_password instead of a raw error", async () => {
    const err = await assertRejects(
      () =>
        assertPasswordPolicy("longenough1", {
          validators: [() => {
            throw new Error("breach service exploded");
          }],
        }),
      IdentityError,
    );
    assertEquals((err as IdentityError).code, "weak_password");
  });

  it("preserves an IdentityError a validator throws itself", async () => {
    const err = await assertRejects(
      () =>
        assertPasswordPolicy("longenough1", {
          validators: [() => {
            throw new IdentityError("rate_limited", "slow down");
          }],
        }),
      IdentityError,
    );
    assertEquals((err as IdentityError).code, "rate_limited");
  });
});
