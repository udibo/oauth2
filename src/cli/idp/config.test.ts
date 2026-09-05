import {
  assertEquals,
  assertMatch,
  assertRejects,
  assertThrows,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  defaultDevIdpConfig,
  loadDevIdpConfig,
  parseDevIdpConfig,
} from "./config.ts";

async function withConfigFile(
  contents: string,
  fn: (path: string) => Promise<void>,
): Promise<void> {
  const path = await Deno.makeTempFile({ suffix: ".json" });
  try {
    await Deno.writeTextFile(path, contents);
    await fn(path);
  } finally {
    await Deno.remove(path);
  }
}

describe("parseDevIdpConfig", () => {
  it("fills every default so the server has nothing left to resolve", () => {
    const config = parseDevIdpConfig({});

    assertEquals(config.port, 9000);
    assertEquals(config.hostname, "127.0.0.1");
    assertEquals(config.consent, "auto");
    assertEquals(config.grants.authorization_code, true);
    assertEquals(config.grants.password, false);
    assertEquals(config.users, defaultDevIdpConfig().users);
  });

  it("defaults a user's id to its username and its claims to none", () => {
    const config = parseDevIdpConfig({
      users: [{ username: "dev@example.com", password: "hunter2" }],
      clients: [],
    });

    assertEquals(config.users[0].id, "dev@example.com");
    assertEquals(config.users[0].claims, {});
  });

  it("keeps declared users, clients, and scopes", () => {
    const config = parseDevIdpConfig({
      issuer: "https://idp.test",
      port: 4444,
      consent: "prompt",
      scopesSupported: ["openid", "orders:read"],
      users: [{
        id: "u1",
        username: "dev",
        password: "pw",
        claims: { name: "Dev" },
      }],
      clients: [{
        id: "web",
        secret: "s3cret",
        redirectUris: ["http://localhost:4000/cb"],
        grants: ["authorization_code"],
      }],
    });

    assertEquals(config.issuer, "https://idp.test");
    assertEquals(config.port, 4444);
    assertEquals(config.consent, "prompt");
    assertEquals(config.scopesSupported, ["openid", "orders:read"]);
    assertEquals(config.users[0].claims, { name: "Dev" });
    assertEquals(config.clients[0].secret, "s3cret");
  });

  it("rejects an unknown field instead of ignoring the typo", () => {
    assertThrows(
      () => parseDevIdpConfig({ user: [] }),
      Error,
      "config.user is not a known option",
    );
  });

  it("names the path of a missing or mistyped field", () => {
    assertThrows(
      () => parseDevIdpConfig({ users: [{ username: "dev" }], clients: [] }),
      Error,
      "users[0].password must be a non-empty string",
    );
    assertThrows(
      () => parseDevIdpConfig({ port: "9000" }),
      Error,
      "config.port must be an integer >= 0",
    );
    assertThrows(
      () => parseDevIdpConfig({ consent: "maybe" }),
      Error,
      'config.consent must be "auto" or "prompt"',
    );
  });

  it("requires a redirect URI for an authorization_code client", () => {
    assertThrows(
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
    assertThrows(
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
    assertThrows(
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
    assertThrows(
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
        clients: [{
          id: "web",
          redirectUris: ["http://localhost:4000/cb"],
        }],
      }),
      async (path) => {
        const config = await loadDevIdpConfig(path);
        assertEquals(config.port, 4100);
        assertEquals(config.users[0].username, "dev");
        assertEquals(config.clients[0].grants, [
          "authorization_code",
          "refresh_token",
        ]);
      },
    );
  });

  it("names the file when the JSON is malformed", async () => {
    await withConfigFile("{ not json", async (path) => {
      const error = await assertRejects(
        () => loadDevIdpConfig(path),
        Error,
      );
      assertMatch(error.message, /is not valid JSON/);
      assertEquals(error.message.includes(path), true);
    });
  });

  it("names the file when a field is invalid", async () => {
    await withConfigFile(JSON.stringify({ port: -1 }), async (path) => {
      const error = await assertRejects(() => loadDevIdpConfig(path), Error);
      assertMatch(error.message, /config.port must be an integer/);
      assertEquals(error.message.includes(path), true);
    });
  });

  it("reports a missing file without a stack of Deno internals", async () => {
    const error = await assertRejects(
      () => loadDevIdpConfig("/nonexistent/idp.json"),
      Error,
    );
    assertMatch(error.message, /cannot read config \/nonexistent\/idp.json/);
  });
});
