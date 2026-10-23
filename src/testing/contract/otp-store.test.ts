import { describe, expect, it } from "vitest";
import { runSuiteInChild } from "./_test_child.ts";

describe("runOtpStoreContractTests rejects faulty stores", () => {
  const cases: [fault: string, failing: string[]][] = [
    [
      "consume-keeps-older",
      [
        "faulty OtpStore consume retires every older active code for the pair",
        "faulty OtpStore EmailOtpService over the store leaves no older code redeemable after a successful verify",
      ],
    ],
    [
      "consume-retires-newer",
      [
        "faulty OtpStore consume leaves a code newer than the claimed one active",
      ],
    ],
    [
      "failed-consume-retires",
      ["faulty OtpStore consume retires nothing when the claim fails"],
    ],
    [
      "consume-retires-every-pair",
      ["faulty OtpStore consume leaves other emails and other purposes active"],
    ],
    [
      "find-active-by-insertion",
      [
        "faulty OtpStore create / findActive returns the greatest createdAt, not the last inserted",
      ],
    ],
    [
      "one-code-store-keeps-replaced-id",
      [
        "faulty OtpStore EmailOtpService over the store leaves no older code redeemable after a successful verify",
        "faulty OtpStore consume retires every older active code for the pair",
        "faulty OtpStore create / findActive replaces the pair's active code (oneActiveCode)",
        "faulty OtpStore create / findActive returns the most recently created active record",
        "faulty OtpStore invalidateById leaves a newer code active",
      ],
    ],
    [
      "one-code-store-as-many",
      [
        "faulty OtpStore create / findActive returns the greatest createdAt, not the last inserted",
        "faulty OtpStore consume leaves a code newer than the claimed one active",
        "faulty OtpStore consume retires nothing when the claim fails",
        "faulty OtpStore invalidateById deactivates only the named record",
      ],
    ],
    [
      "many-code-store-as-one",
      [
        "faulty OtpStore create / findActive replaces the pair's active code (oneActiveCode)",
      ],
    ],
  ];

  for (const [fault, failing] of cases) {
    it(fault, async () => {
      const run = await runSuiteInChild(
        "src/testing/contract/_test_otp_store_faults.ts",
        { OTP_STORE_FAULT: fault },
      );
      expect(
        run.exitCode,
        `the suite must fail this store:\n${run.output}`,
      ).not.toBe(0);
      expect(
        run.tests
          .filter((test) => test.status === "failed")
          .map((test) => test.fullName)
          .sort(),
      ).toStrictEqual([...failing].sort());
    });
  }
});
