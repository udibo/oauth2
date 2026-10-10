import { describe, expect, it } from "vitest";

import { parseConfig } from "./config.ts";

describe("parseConfig", () => {
  it("runs locally with no variables set", () => {
    expect(parseConfig({})).toEqual({
      origin: "http://localhost:8000",
      port: 8000,
      isProduction: false,
      secureCookies: false,
      clientSecret: "dev-only-secret",
    });
  });

  it("derives Secure cookies from an https origin and drops any path", () => {
    const config = parseConfig({ ORIGIN: "https://app.example.com/ignored" });
    expect(config.origin).toBe("https://app.example.com");
    expect(config.secureCookies).toBe(true);
  });

  it("uses the secret and port it is given", () => {
    const config = parseConfig({
      OAUTH2_CLIENT_SECRET: "from-the-vault",
      PORT: "3100",
    });
    expect(config.clientSecret).toBe("from-the-vault");
    expect(config.port).toBe(3100);
  });

  it("refuses to start in production without a client secret", () => {
    expect(() => parseConfig({ APP_ENV: "production" })).toThrow(
      /OAUTH2_CLIENT_SECRET: must be set when APP_ENV=production/,
    );
  });

  it("starts in production with a client secret", () => {
    const config = parseConfig({
      APP_ENV: "production",
      OAUTH2_CLIENT_SECRET: "from-the-vault",
    });
    expect(config.isProduction).toBe(true);
  });

  it("lists every invalid variable in one error", () => {
    expect(() =>
      parseConfig({ ORIGIN: "not a url", PORT: "99999", APP_ENV: "staging" }),
    ).toThrow(/ORIGIN[\s\S]*PORT[\s\S]*APP_ENV/);
  });
});
