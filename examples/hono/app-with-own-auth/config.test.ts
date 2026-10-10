import { describe, expect, it } from "vitest";

import { ConfigError, loadConfig } from "./config.ts";

describe("loadConfig", () => {
  it("matches the companion examples' local ports when nothing is set", () => {
    expect(loadConfig({})).toEqual({
      port: 8001,
      publicUrl: "http://localhost:8001",
      apiServiceOrigin: "http://localhost:8002",
      externalAppOrigin: "http://localhost:8003",
    });
  });

  it("derives the public URL, and so the issuer, from PORT when PUBLIC_URL is unset", () => {
    expect(loadConfig({ PORT: "9001" }).publicUrl).toBe(
      "http://localhost:9001",
    );
  });

  it("reads every setting from the environment", () => {
    expect(
      loadConfig({
        PORT: "3000",
        PUBLIC_URL: "https://id.example.com",
        API_SERVICE_ORIGIN: "https://api.example.com",
        EXTERNAL_APP_ORIGIN: "https://app.example.com",
      }),
    ).toEqual({
      port: 3000,
      publicUrl: "https://id.example.com",
      apiServiceOrigin: "https://api.example.com",
      externalAppOrigin: "https://app.example.com",
    });
  });

  it("reports every invalid variable in one error", () => {
    const error = (() => {
      try {
        loadConfig({
          PORT: "1.5",
          PUBLIC_URL: "localhost",
          EXTERNAL_APP_ORIGIN: "ws://app.example.com",
        });
      } catch (caught) {
        return caught;
      }
    })();
    expect(error).toBeInstanceOf(ConfigError);
    expect((error as ConfigError).problems).toEqual([
      'PORT must be an integer from 0 to 65535, got "1.5"',
      'PUBLIC_URL must be an http(s) URL, got "localhost"',
      'EXTERNAL_APP_ORIGIN must be an http(s) URL, got "ws://app.example.com"',
    ]);
  });
});
