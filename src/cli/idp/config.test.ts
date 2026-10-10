import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { rejection, thrown } from "../../_test_assert.ts";
import {
  defaultDevIdpConfig,
  loadDevIdpConfig,
  parseDevIdpConfig,
} from "./config.ts";

async function withConfigFile(
  contents: string,
  fn: (path: string) => Promise<void>,
): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "oauth2-idp-config-"));
  try {
    const path = join(directory, "idp.json");
    await writeFile(path, contents);
    await fn(path);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe("parseDevIdpConfig", () => {
  it("fills every default so the server has nothing left to resolve", () => {
    const config = parseDevIdpConfig({});

    expect(config.port).toStrictEqual(9000);
    expect(config.hostname).toStrictEqual("127.0.0.1");
    expect(config.consent).toStrictEqual("auto");
    expect(config.grants.authorization_code).toStrictEqual(true);
    expect(config.grants.password).toStrictEqual(false);
    expect(config.users).toStrictEqual(defaultDevIdpConfig().users);
  });

  it("defaults a user's id to its username and its claims to none", () => {
    const config = parseDevIdpConfig({
      users: [{ username: "dev@example.com", password: "hunter2" }],
      clients: [],
    });

    expect(config.users[0].id).toStrictEqual("dev@example.com");
    expect(config.users[0].claims).toStrictEqual({});
  });

  it("keeps declared users, clients, and scopes", () => {
    const config = parseDevIdpConfig({
      issuer: "https://idp.test",
      port: 4444,
      consent: "prompt",
      scopesSupported: ["openid", "orders:read"],
      users: [
        {
          id: "u1",
          username: "dev",
          password: "pw",
          claims: { name: "Dev" },
        },
      ],
      clients: [
        {
          id: "web",
          secret: "s3cret",
          redirectUris: ["http://localhost:4000/cb"],
          grants: ["authorization_code"],
        },
      ],
    });

    expect(config.issuer).toStrictEqual("https://idp.test");
    expect(config.port).toStrictEqual(4444);
    expect(config.consent).toStrictEqual("prompt");
    expect(config.scopesSupported).toStrictEqual(["openid", "orders:read"]);
    expect(config.users[0].claims).toStrictEqual({ name: "Dev" });
    expect(config.clients[0].secret).toStrictEqual("s3cret");
  });

  it("rejects an unknown field instead of ignoring the typo", () => {
    thrown(
      () => parseDevIdpConfig({ user: [] }),
      Error,
      "config.user is not a known option",
    );
  });

  it("names the path of a missing or mistyped field", () => {
    thrown(
      () => parseDevIdpConfig({ users: [{ username: "dev" }], clients: [] }),
      Error,
      "users[0].password must be a non-empty string",
    );
    thrown(
      () => parseDevIdpConfig({ port: "9000" }),
      Error,
      "config.port must be an integer >= 0",
    );
    thrown(
      () => parseDevIdpConfig({ consent: "maybe" }),
      Error,
      'config.consent must be "auto" or "prompt"',
    );
  });

  it("names the path of a grant flag or collection of the wrong type", () => {
    thrown(
      () => parseDevIdpConfig({ grants: { password: "yes" } }),
      Error,
      "config.grants.password must be true or false",
    );
    thrown(
      () => parseDevIdpConfig({ grants: [] }),
      Error,
      "config.grants must be an object",
    );
    thrown(
      () => parseDevIdpConfig({ users: {} }),
      Error,
      "config.users must be an array",
    );
    thrown(
      () => parseDevIdpConfig({ accessTokenLifetime: 0 }),
      Error,
      "config.accessTokenLifetime must be an integer >= 1",
    );
  });

  it("requires a redirect URI for an authorization_code client", () => {
    thrown(
      () =>
        parseDevIdpConfig({
          users: [],
          clients: [{ id: "web", grants: ["authorization_code"] }],
        }),
      Error,
      "clients[0].redirectUris must list at least one URI",
    );
  });

  it("rejects duplicate user and client ids", () => {
    thrown(
      () =>
        parseDevIdpConfig({
          users: [
            { username: "dev", password: "pw" },
            { username: "dev", password: "pw" },
          ],
          clients: [],
        }),
      Error,
      'more than one user with id "dev"',
    );
    thrown(
      () =>
        parseDevIdpConfig({
          users: [],
          clients: [
            { id: "web", grants: ["client_credentials"] },
            { id: "web", grants: ["client_credentials"] },
          ],
        }),
      Error,
      'more than one client with id "web"',
    );
  });

  it("requires a private JWK when a signing key is pinned", () => {
    thrown(
      () => parseDevIdpConfig({ signingKey: { kty: "EC" } }),
      Error,
      "config.signingKey.d must be a non-empty string",
    );
  });
});

describe("loadDevIdpConfig", () => {
  it("reads and validates a config file", async () => {
    await withConfigFile(
      JSON.stringify({
        port: 4100,
        users: [{ username: "dev", password: "pw" }],
        clients: [
          {
            id: "web",
            redirectUris: ["http://localhost:4000/cb"],
          },
        ],
      }),
      async (path) => {
        const config = await loadDevIdpConfig(path);
        expect(config.port).toStrictEqual(4100);
        expect(config.users[0].username).toStrictEqual("dev");
        expect(config.clients[0].grants).toStrictEqual([
          "authorization_code",
          "refresh_token",
        ]);
      },
    );
  });

  it("names the file when the JSON is malformed", async () => {
    await withConfigFile("{ not json", async (path) => {
      const error = await rejection(() => loadDevIdpConfig(path), Error);
      expect(error.message).toMatch(/is not valid JSON/);
      expect(error.message.includes(path)).toStrictEqual(true);
    });
  });

  it("names the file when a field is invalid", async () => {
    await withConfigFile(JSON.stringify({ port: -1 }), async (path) => {
      const error = await rejection(() => loadDevIdpConfig(path), Error);
      expect(error.message).toMatch(/config.port must be an integer/);
      expect(error.message.includes(path)).toStrictEqual(true);
    });
  });

  it("reports a missing file by name", async () => {
    const error = await rejection(
      () => loadDevIdpConfig("/nonexistent/idp.json"),
      Error,
    );
    expect(error.message).toMatch(/cannot read config \/nonexistent\/idp.json/);
  });
});
