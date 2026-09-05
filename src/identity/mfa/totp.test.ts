import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { encodeBase32 } from "@std/encoding/base32";

import {
  buildOtpauthUri,
  decodeTotpSecret,
  generateTotpCode,
  generateTotpSecret,
  type TotpAlgorithm,
  verifyTotpCode,
} from "./totp.ts";

const RFC_SEEDS: Record<TotpAlgorithm, Uint8Array> = {
  "SHA-1": new TextEncoder().encode("12345678901234567890"),
  "SHA-256": new TextEncoder().encode("12345678901234567890123456789012"),
  "SHA-512": new TextEncoder().encode(
    "1234567890123456789012345678901234567890123456789012345678901234",
  ),
};

const RFC_VECTORS: Array<
  { seconds: number; codes: Record<TotpAlgorithm, string> }
> = [
  {
    seconds: 59,
    codes: {
      "SHA-1": "94287082",
      "SHA-256": "46119246",
      "SHA-512": "90693936",
    },
  },
  {
    seconds: 1111111109,
    codes: {
      "SHA-1": "07081804",
      "SHA-256": "68084774",
      "SHA-512": "25091201",
    },
  },
  {
    seconds: 1111111111,
    codes: {
      "SHA-1": "14050471",
      "SHA-256": "67062674",
      "SHA-512": "99943326",
    },
  },
  {
    seconds: 1234567890,
    codes: {
      "SHA-1": "89005924",
      "SHA-256": "91819424",
      "SHA-512": "93441116",
    },
  },
  {
    seconds: 2000000000,
    codes: {
      "SHA-1": "69279037",
      "SHA-256": "90698825",
      "SHA-512": "38618901",
    },
  },
  {
    seconds: 20000000000,
    codes: {
      "SHA-1": "65353130",
      "SHA-256": "77737706",
      "SHA-512": "47863826",
    },
  },
];

const ALGORITHMS: TotpAlgorithm[] = ["SHA-1", "SHA-256", "SHA-512"];

describe("generateTotpCode", () => {
  for (const algorithm of ALGORITHMS) {
    it(`matches the RFC 6238 Appendix B vectors for ${algorithm}`, async () => {
      for (const vector of RFC_VECTORS) {
        assertEquals(
          await generateTotpCode({
            secret: RFC_SEEDS[algorithm],
            timestamp: vector.seconds * 1000,
            digits: 8,
            algorithm,
          }),
          vector.codes[algorithm],
        );
      }
    });
  }

  it("accepts the secret as a base32 string, unpadded or padded or lowercase", async () => {
    const seed = RFC_SEEDS["SHA-1"];
    const padded = encodeBase32(seed);
    const unpadded = padded.replaceAll("=", "");
    for (const secret of [padded, unpadded, unpadded.toLowerCase()]) {
      assertEquals(
        await generateTotpCode({
          secret,
          timestamp: 59_000,
          digits: 8,
        }),
        "94287082",
      );
    }
  });

  it("defaults to 6 digits, zero-padded", async () => {
    const code = await generateTotpCode({
      secret: RFC_SEEDS["SHA-1"],
      timestamp: 59_000,
    });
    assertEquals(code, "287082");
    assertEquals(code.length, 6);
  });
});

describe("generateTotpSecret", () => {
  it("returns 20 random bytes with an unpadded base32 round-trip", () => {
    const { secret, base32 } = generateTotpSecret();
    assertEquals(secret.length, 20);
    assert(/^[A-Z2-7]{32}$/.test(base32));
    assertEquals(decodeTotpSecret(base32), secret);
  });

  it("returns a different secret each call", () => {
    assert(generateTotpSecret().base32 !== generateTotpSecret().base32);
  });
});

describe("decodeTotpSecret", () => {
  it("tolerates lowercase, whitespace, and missing padding", () => {
    const { secret, base32 } = generateTotpSecret();
    assertEquals(decodeTotpSecret(base32.toLowerCase()), secret);
    assertEquals(
      decodeTotpSecret(`${base32.slice(0, 4)} ${base32.slice(4)}`),
      secret,
    );
    assertEquals(decodeTotpSecret(`${base32}========`.slice(0, 40)), secret);
  });

  it("rejects values that are not base32", () => {
    assertThrows(() => decodeTotpSecret("not base32!"), TypeError);
  });
});

describe("verifyTotpCode", () => {
  const secret = RFC_SEEDS["SHA-1"];

  it("accepts the exact-step code and reports the matched step", async () => {
    const result = await verifyTotpCode({
      secret,
      code: "94287082",
      timestamp: 59_000,
      digits: 8,
      windows: 0,
    });
    assertEquals(result, { valid: true, matchedStep: 1 });
  });

  it("accepts one step of skew either side by default and rejects beyond it", async () => {
    const timestamp = 1_111_111_111_000;
    const code = await generateTotpCode({ secret, timestamp });
    for (const skewSteps of [-1, 0, 1]) {
      const result = await verifyTotpCode({
        secret,
        code,
        timestamp: timestamp + skewSteps * 30_000,
      });
      assert(result.valid, `skew ${skewSteps}`);
      assertEquals(result.matchedStep, Math.floor(timestamp / 30_000));
    }
    for (const skewSteps of [-2, 2]) {
      assertEquals(
        await verifyTotpCode({
          secret,
          code,
          timestamp: timestamp + skewSteps * 30_000,
        }),
        { valid: false },
        `skew ${skewSteps}`,
      );
    }
  });

  it("widens acceptance with a larger windows option", async () => {
    const timestamp = 1_111_111_111_000;
    const code = await generateTotpCode({ secret, timestamp });
    const result = await verifyTotpCode({
      secret,
      code,
      timestamp: timestamp + 60_000,
      windows: 2,
    });
    assertEquals(result.valid, true);
  });

  it("rejects a zero-window verify of a neighboring step's code", async () => {
    const timestamp = 1_111_111_111_000;
    const code = await generateTotpCode({
      secret,
      timestamp: timestamp - 30_000,
    });
    assertEquals(
      await verifyTotpCode({ secret, code, timestamp, windows: 0 }),
      { valid: false },
    );
  });

  it("rejects malformed codes without leaking a matched step", async () => {
    for (const code of ["", "12345", "1234567", "94287o82", "castle"]) {
      assertEquals(
        await verifyTotpCode({ secret, code, timestamp: 59_000, digits: 8 }),
        { valid: false },
        code,
      );
    }
  });

  it("accepts a code pasted with the spaced grouping authenticator apps display", async () => {
    const result = await verifyTotpCode({
      secret,
      code: "9428 7082",
      timestamp: 59_000,
      digits: 8,
      windows: 0,
    });
    assertEquals(result, { valid: true, matchedStep: 1 });
  });

  it("prefers the newest step when adjacent steps produce the same code", async () => {
    let step = 1;
    let code = await generateTotpCode({ secret, timestamp: 0, digits: 1 });
    for (;;) {
      const next = await generateTotpCode({
        secret,
        timestamp: step * 30_000,
        digits: 1,
      });
      if (next === code) break;
      code = next;
      step++;
      assert(step < 1000, "no adjacent-step collision found");
    }
    const result = await verifyTotpCode({
      secret,
      code,
      timestamp: step * 30_000,
      digits: 1,
    });
    assertEquals(result, { valid: true, matchedStep: step });
  });

  it("rejects unusable digits, period, or windows configuration", async () => {
    await assertRejects(
      () => verifyTotpCode({ secret, code: "123456", digits: 6.5 }),
      TypeError,
    );
    await assertRejects(
      () => verifyTotpCode({ secret, code: "123456", periodSeconds: 0 }),
      TypeError,
    );
    await assertRejects(
      () => verifyTotpCode({ secret, code: "123456", windows: -1 }),
      TypeError,
    );
    await assertRejects(
      () => generateTotpCode({ secret, digits: 0 }),
      TypeError,
    );
  });

  it("skips negative time steps at the epoch boundary", async () => {
    const code = await generateTotpCode({ secret, timestamp: 0 });
    const result = await verifyTotpCode({ secret, code, timestamp: 0 });
    assertEquals(result, { valid: true, matchedStep: 0 });
  });

  it("supports the replay contract: the same step never exceeds a stored lastStep", async () => {
    const timestamp = 1_111_111_111_000;
    const code = await generateTotpCode({ secret, timestamp });
    const first = await verifyTotpCode({ secret, code, timestamp });
    assert(first.valid);
    const lastStep = first.matchedStep;
    const replay = await verifyTotpCode({
      secret,
      code,
      timestamp: timestamp + 30_000,
    });
    assert(replay.valid);
    assert(replay.matchedStep <= lastStep);
    const next = await verifyTotpCode({
      secret,
      code: await generateTotpCode({ secret, timestamp: timestamp + 30_000 }),
      timestamp: timestamp + 30_000,
    });
    assert(next.valid);
    assert(next.matchedStep > lastStep);
  });
});

describe("buildOtpauthUri", () => {
  it("URI-encodes the issuer into both the label and the query parameter", () => {
    const uri = buildOtpauthUri({
      secret: "JBSWY3DPEHPK3PXP",
      issuer: "Udibo App",
      accountName: "user+tag@example.com",
    });
    assertEquals(
      uri,
      "otpauth://totp/Udibo%20App:user%2Btag%40example.com" +
        "?secret=JBSWY3DPEHPK3PXP&issuer=Udibo%20App&algorithm=SHA1&digits=6&period=30",
    );
  });

  it("renders non-default digits, period, and algorithm", () => {
    const uri = buildOtpauthUri({
      secret: "JBSWY3DPEHPK3PXP",
      issuer: "Udibo",
      accountName: "a@b.co",
      digits: 8,
      periodSeconds: 60,
      algorithm: "SHA-256",
    });
    assertStringIncludes(uri, "algorithm=SHA256");
    assertStringIncludes(uri, "digits=8");
    assertStringIncludes(uri, "period=60");
  });

  it("normalizes the secret to uppercase without padding", () => {
    const uri = buildOtpauthUri({
      secret: "jbswy3dpehpk3pxp====",
      issuer: "Udibo",
      accountName: "a@b.co",
    });
    assertStringIncludes(uri, "secret=JBSWY3DPEHPK3PXP&");
  });

  it("rejects a non-base32 secret so it cannot inject URI parameters", () => {
    assertThrows(
      () =>
        buildOtpauthUri({
          secret: "ABC&algorithm=SHA256",
          issuer: "Udibo",
          accountName: "a@b.co",
        }),
      TypeError,
    );
  });

  it("rejects non-positive-integer digits and period", () => {
    for (const digits of [0, -1, 6.5]) {
      assertThrows(
        () =>
          buildOtpauthUri({
            secret: "JBSWY3DPEHPK3PXP",
            issuer: "Udibo",
            accountName: "a@b.co",
            digits,
          }),
        TypeError,
      );
    }
    assertThrows(
      () =>
        buildOtpauthUri({
          secret: "JBSWY3DPEHPK3PXP",
          issuer: "Udibo",
          accountName: "a@b.co",
          periodSeconds: 0,
        }),
      TypeError,
    );
  });
});
