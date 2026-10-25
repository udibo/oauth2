import { randomBytes } from "node:crypto";

import type { Hono } from "hono";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from "vitest";

describe("server entry request logging", () => {
  let server: Hono;
  let log: MockInstance<typeof console.log>;
  let output = "";

  beforeAll(async () => {
    vi.stubEnv("NODE_ENV", "development");
    log = vi.spyOn(console, "log").mockImplementation((...args) => {
      output += `${args.join(" ")}\n`;
    });
    using _missingStaticRoots = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    ({ default: server } = await import("./index.ts"));
  });

  beforeEach(() => {
    output = "";
  });

  afterAll(() => {
    log.mockRestore();
    vi.unstubAllEnvs();
  });

  it.each([
    ["/auth/callback", ["code", "state"]],
    ["/reset-password", ["token"]],
    ["/verify-email", ["token"]],
  ])(
    "logs %s with its query values redacted, never the values themselves",
    async (path, names) => {
      const secrets = names.map(() => randomBytes(16).toString("hex"));
      const query = names
        .map((name, index) => `${name}=${secrets[index]}`)
        .join("&");
      await server.request(`${path}?${query}`, {}, {});
      const redacted = names.map((name) => `${name}=[redacted]`).join("&");
      expect(output).toContain(`${path}?${redacted}`);
      for (const secret of secrets) expect(output).not.toContain(secret);
    },
  );
});
