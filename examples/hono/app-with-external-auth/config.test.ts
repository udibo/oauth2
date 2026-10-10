import { describe, expect, it } from "vitest";

import { ConfigError, loadConfig } from "./config.ts";

describe("loadConfig", () => {
  it("pairs with app-with-own-auth and api-service on localhost when nothing is set", () => {
    expect(loadConfig({})).toEqual({
      port: 8003,
      publicUrl: "http://localhost:8003",
      idpBaseUrl: "http://localhost:8001",
      idpClientId: "spa",
      idpClientSecret: "spa-secret",
      apiServiceUrl: "http://localhost:8002/api",
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
        PORT: "3000",
        PUBLIC_URL: "https://app.example.com",
        IDP_BASE_URL: "https://id.udibo.com",
        IDP_CLIENT_ID: "my-app",
        IDP_CLIENT_SECRET: "s3cret",
        API_SERVICE_URL: "https://api.example.com/v1/",
      }),
    ).toEqual({
      port: 3000,
      publicUrl: "https://app.example.com",
      idpBaseUrl: "https://id.udibo.com",
      idpClientId: "my-app",
      idpClientSecret: "s3cret",
      apiServiceUrl: "https://api.example.com/v1",
    });
  });

  it("reports every invalid variable in one error", () => {
    const error = (() => {
      try {
        loadConfig({
          PORT: "-1",
          IDP_BASE_URL: "idp",
          API_SERVICE_URL: "ftp://api.example.com",
        });
      } catch (caught) {
        return caught;
      }
    })();
    expect(error).toBeInstanceOf(ConfigError);
    expect((error as ConfigError).problems).toEqual([
      'PORT must be an integer from 0 to 65535, got "-1"',
      'IDP_BASE_URL must be an http(s) URL, got "idp"',
      'API_SERVICE_URL must be an http(s) URL, got "ftp://api.example.com"',
    ]);
  });
});
