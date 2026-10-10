import { describe, expect, it } from "vitest";

import { ConfigError, loadConfig } from "./config.ts";

describe("loadConfig", () => {
  it("pairs with app-with-own-auth on localhost when nothing is set", () => {
    expect(loadConfig({})).toEqual({
      port: 8002,
      publicUrl: "http://localhost:8002",
      authServerUrl: "http://localhost:8001",
      clientId: "spa",
      clientSecret: "spa-secret",
    });
  });

  it("derives the public URL from PORT when PUBLIC_URL is unset", () => {
    expect(loadConfig({ PORT: "9100" }).publicUrl).toBe(
      "http://localhost:9100",
    );
  });

  it("reads every setting from the environment", () => {
    expect(
      loadConfig({
        PORT: "0",
        PUBLIC_URL: "https://api.example.com/ignored/path",
        AUTH_SERVER_URL: "https://idp.example.com",
        CLIENT_ID: "billing",
        CLIENT_SECRET: "s3cret",
      }),
    ).toEqual({
      port: 0,
      publicUrl: "https://api.example.com",
      authServerUrl: "https://idp.example.com",
      clientId: "billing",
      clientSecret: "s3cret",
    });
  });

  it("reports every invalid variable in one error", () => {
    const error = (() => {
      try {
        loadConfig({
          PORT: "eighty",
          PUBLIC_URL: "ftp://example.com",
          AUTH_SERVER_URL: "not a url",
        });
      } catch (caught) {
        return caught;
      }
    })();
    expect(error).toBeInstanceOf(ConfigError);
    expect((error as ConfigError).problems).toEqual([
      'PORT must be an integer from 0 to 65535, got "eighty"',
      'PUBLIC_URL must be an http(s) URL, got "ftp://example.com"',
      'AUTH_SERVER_URL must be an http(s) URL, got "not a url"',
    ]);
  });

  it("rejects a port outside the valid range", () => {
    expect(() => loadConfig({ PORT: "70000" })).toThrow(ConfigError);
  });
});
