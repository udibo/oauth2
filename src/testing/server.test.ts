import { assertEquals, assertRejects, assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { encodeBasicAuth } from "../utils/basic-auth.ts";
import { DirectClient } from "../client/direct-client.ts";
import { ResourceServer } from "../server/resource-server.ts";
import { createMemoryAuthorizationServer } from "./server.ts";

describe("createMemoryAuthorizationServer", () => {
  it("seeds users + clients and exposes a fetch that dispatches in-process", async () => {
    const oauth = await createMemoryAuthorizationServer({
      issuer: "http://localhost",
      users: [{
        user: { id: "u1", username: "alice" },
        password: "password",
      }],
      clients: [{
        client: {
          id: "client-1",
          grants: [
            "client_credentials",
            "authorization_code",
            "refresh_token",
          ],
          redirectUris: ["http://app/cb"],
        },
        secret: "secret",
        ownerUserId: "u1",
      }],
    });

    const tokenResponse = await oauth.fetch(
      "http://localhost/oauth2/token",
      {
        method: "POST",
        headers: {
          Authorization: encodeBasicAuth("client-1", "secret"),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({ grant_type: "client_credentials" }),
      },
    );
    assertStrictEquals(tokenResponse.status, 200);
    const body = await tokenResponse.json();
    assertStrictEquals(body.token_type, "Bearer");
    assertStrictEquals(typeof body.access_token, "string");
  });

  it("mints, introspects, validates and revokes a token for a client seeded without a user", async () => {
    const oauth = await createMemoryAuthorizationServer({
      issuer: "http://localhost",
      clients: [{
        client: { id: "m2m", grants: ["client_credentials"] },
        secret: "s",
      }],
    });
    const authorization = encodeBasicAuth("m2m", "s");
    const post = (path: string, params: Record<string, string>) =>
      oauth.fetch(`http://localhost/oauth2/${path}`, {
        method: "POST",
        headers: {
          Authorization: authorization,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams(params),
      });

    const tokenResponse = await post("token", {
      grant_type: "client_credentials",
      scope: "read",
    });
    assertStrictEquals(tokenResponse.status, 200);
    const { access_token: accessToken } = await tokenResponse.json();
    assertStrictEquals(typeof accessToken, "string");

    const introspection = await (await post("introspect", {
      token: accessToken,
    })).json();
    assertStrictEquals(introspection.active, true);
    assertStrictEquals(introspection.client_id, "m2m");
    assertStrictEquals(introspection.sub, undefined);
    assertStrictEquals(introspection.username, undefined);

    const resourceServer = new ResourceServer({
      resolve: () => ({
        services: { tokenService: oauth.services.tokenService },
      }),
    });
    const context = await resourceServer.authenticate(
      new Request("http://api.localhost/resource", {
        headers: { Authorization: `Bearer ${accessToken}` },
      }),
      "read",
    );
    assertStrictEquals(context.client.id, "m2m");
    assertStrictEquals(context.user, undefined);

    assertStrictEquals(
      (await post("revoke", { token: accessToken })).status,
      200,
    );
    const afterRevocation = await (await post("introspect", {
      token: accessToken,
    })).json();
    assertStrictEquals(afterRevocation.active, false);
  });

  it("publishes server metadata that reflects the configured grants", async () => {
    const oauth = await createMemoryAuthorizationServer({
      issuer: "http://localhost",
      grants: { authorization_code: true, client_credentials: false },
    });
    const metaResponse = await oauth.fetch(
      "http://localhost/.well-known/oauth-authorization-server",
    );
    assertStrictEquals(metaResponse.status, 200);
    const metadata = await metaResponse.json();
    assertEquals(metadata.issuer, "http://localhost");
    assertEquals(
      metadata.grant_types_supported.includes("authorization_code"),
      true,
    );
    assertEquals(
      metadata.grant_types_supported.includes("client_credentials"),
      false,
    );
  });

  it("can be injected into a DirectClient's fetch option", async () => {
    const oauth = await createMemoryAuthorizationServer({
      issuer: "http://localhost",
      users: [{
        user: { id: "service-user", username: "m2m-owner" },
        password: "irrelevant",
      }],
      clients: [{
        client: { id: "m2m", grants: ["client_credentials"] },
        secret: "shh",
        ownerUserId: "service-user",
      }],
    });

    const client = new DirectClient({
      clientId: "m2m",
      clientSecret: "shh",
      endpoints: { token: "http://localhost/oauth2/token" },
      fetch: oauth.fetch,
    });
    const tokens = await client.getClientCredentialsToken();
    assertStrictEquals(typeof tokens.accessToken, "string");
  });

  it("addUser / addClient seed mid-test", async () => {
    const oauth = await createMemoryAuthorizationServer();
    await oauth.addUser({ id: "u9", username: "late" }, "pw");
    await oauth.addClient(
      { id: "late-client", grants: ["client_credentials"] },
      "s",
    );
    const seededUser = await oauth.services.userService.get("u9");
    assertStrictEquals(seededUser?.username, "late");
    const seededClient = await oauth.services.clientService.get("late-client");
    assertStrictEquals(seededClient?.id, "late-client");
  });

  it("fetch throws an actionable error for the authorization endpoint", async () => {
    const oauth = await createMemoryAuthorizationServer({
      issuer: "http://localhost",
    });
    await assertRejects(
      () =>
        oauth.fetch(
          "http://localhost/oauth2/authorize?response_type=code&client_id=x&state=s",
        ),
      Error,
      "cannot dispatch the authorization endpoint",
    );
  });

  it("authorize() drives the /authorize leg and yields a redeemable code", async () => {
    const oauth = await createMemoryAuthorizationServer({
      issuer: "http://localhost",
      users: [{ user: { id: "u1", username: "alice" }, password: "pw" }],
      clients: [{
        client: {
          id: "spa",
          grants: ["authorization_code", "refresh_token"],
          redirectUris: ["http://app/cb"],
        },
      }],
    });

    const client = new DirectClient({
      clientId: "spa",
      redirectUri: "http://app/cb",
      endpoints: {
        authorization: "http://localhost/oauth2/authorize",
        token: "http://localhost/oauth2/token",
      },
      fetch: oauth.fetch,
    });

    const begin = await client.login({ scope: "read" });
    const redirect = await oauth.authorize(begin.url);
    assertStrictEquals(redirect.status, 302);
    const callbackUrl = redirect.headers.get("Location")!;
    assertEquals(new URL(callbackUrl).searchParams.has("code"), true);

    const result = await client.handleAuthorizationCallback(callbackUrl);
    assertStrictEquals(typeof result.tokens.accessToken, "string");
  });

  it("device authorization is drivable through fetch (default verificationUri)", async () => {
    const oauth = await createMemoryAuthorizationServer({
      issuer: "http://localhost",
      clients: [{
        client: {
          id: "device-client",
          grants: ["urn:ietf:params:oauth:grant-type:device_code"],
        },
      }],
    });
    const res = await oauth.fetch(
      "http://localhost/oauth2/device_authorization",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ client_id: "device-client" }),
      },
    );
    assertStrictEquals(res.status, 200);
    const body = await res.json();
    assertStrictEquals(typeof body.device_code, "string");
    assertStrictEquals(body.verification_uri, "http://localhost/device");
  });
});
