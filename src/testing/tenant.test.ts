import { assert, assertEquals, assertFalse } from "@std/assert";
import { afterAll, beforeAll, describe, it } from "@std/testing/bdd";

import { JwksTokenReader } from "../server/jwks-token-reader.ts";
import { encodeBasicAuth } from "../utils/basic-auth.ts";
import { generateCodeChallenge, generateCodeVerifier } from "../utils/pkce.ts";
import { createFakeTenant, type FakeTenant } from "./tenant.ts";

const APP = { id: "app", secret: "app-secret" };
const MCP = "http://127.0.0.1:1/mcp";
const REDIRECT = "http://app.localhost/auth/callback";

interface Introspection {
  active: boolean;
  sub?: string;
  username?: string;
  permissions?: string[];
  org_id?: string;
  org_slug?: string;
  org_roles?: string[];
}

describe("createFakeTenant", () => {
  let tenant: FakeTenant;
  let server: Deno.HttpServer<Deno.NetAddr>;

  beforeAll(async () => {
    server = Deno.serve(
      { hostname: "127.0.0.1", port: 0, onListen() {} },
      (request) => tenant.fetch(request),
    );
    tenant = await createFakeTenant({
      issuer: `http://127.0.0.1:${server.addr.port}`,
    });
    await tenant.addClient({
      id: APP.id,
      secret: APP.secret,
      redirectUris: [REDIRECT],
    });
    await tenant.addClient({
      id: "mcp-client",
      redirectUris: ["http://127.0.0.1/callback"],
      accessTokenFormat: "jwt",
      audience: MCP,
    });
    await tenant.addUser({
      id: "ada",
      username: "ada",
      name: "Ada Lovelace",
      email: "ada@example.com",
      permissions: ["documents:read"],
    });
    await tenant.addUser({ id: "bob", username: "bob" });
    tenant.addOrganization({ id: "org-acme", slug: "acme" });
    tenant.addOrganization({ id: "org-globex", slug: "globex" });
    tenant.addMember("org-acme", "ada", {
      roles: ["editor"],
      permissions: ["notes:write"],
    });
    tenant.addMember("org-globex", "ada", { permissions: ["notes:delete"] });
    tenant.addMember("org-acme", "bob");
    tenant.registerResourceType("document");
    tenant.grant({
      resource: { type: "document", id: "doc-1" },
      subject: { type: "user", id: "bob" },
      permissions: ["documents:read"],
    });
    tenant.grant({
      resource: { type: "document", id: "doc-2" },
      subject: { type: "organization", id: "org-acme" },
      permissions: ["documents:write"],
    });
  });

  afterAll(async () => {
    await server.shutdown();
  });

  const url = (path: string) => `${tenant.issuer}${path}`;

  async function signIn(
    userId: string,
    organizationId?: string,
  ): Promise<{ access_token: string; refresh_token?: string }> {
    tenant.signInAs(userId, { organizationId });
    const verifier = generateCodeVerifier();
    const authorize = new URL(url("/api/oauth2/authorize"));
    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: APP.id,
      redirect_uri: REDIRECT,
      scope: "openid profile email offline_access",
      state: "state-1",
      code_challenge: await generateCodeChallenge(verifier),
      code_challenge_method: "S256",
    }).toString();
    const redirect = await fetch(authorize, { redirect: "manual" });
    await redirect.body?.cancel();
    const code = new URL(redirect.headers.get("location")!).searchParams.get(
      "code",
    );
    assert(code, `authorize answered ${redirect.status} without a code`);
    return await token({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    });
  }

  async function token(
    body: Record<string, string>,
  ): Promise<{ access_token: string; refresh_token?: string }> {
    const response = await fetch(url("/api/oauth2/token"), {
      method: "POST",
      headers: { authorization: encodeBasicAuth(APP.id, APP.secret) },
      body: new URLSearchParams(body),
    });
    assertEquals(response.status, 200, await response.clone().text());
    return await response.json();
  }

  async function introspect(accessToken: string): Promise<Introspection> {
    const response = await fetch(url("/api/oauth2/introspect"), {
      method: "POST",
      headers: { authorization: encodeBasicAuth(APP.id, APP.secret) },
      body: new URLSearchParams({ token: accessToken }),
    });
    return await response.json();
  }

  async function ask(
    accessToken: string,
    path: string,
    body: unknown,
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const response = await fetch(url(path), {
      method: "POST",
      headers: {
        authorization: `Bearer ${accessToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  }

  it("advertises its endpoints on the issuer it was given", async () => {
    const metadata = await (await fetch(
      url("/.well-known/oauth-authorization-server"),
    )).json();
    assertEquals(metadata.issuer, tenant.issuer);
    assertEquals(
      metadata.introspection_endpoint,
      url("/api/oauth2/introspect"),
    );
    assertEquals(metadata.jwks_uri, url("/api/oauth2/jwks"));
  });

  it("signs in the person it was told to, with their tenant-wide permissions", async () => {
    const { access_token } = await signIn("ada");
    const claims = await introspect(access_token);
    assertEquals(claims.active, true);
    assertEquals(claims.sub, "ada");
    assertEquals(claims.username, "ada");
    assertEquals(claims.permissions, ["documents:read"]);
    assertFalse(
      "org_id" in claims,
      "a sign-in with no organization names none",
    );
  });

  it("adds the organization picked at sign-in, and only that one", async () => {
    const { access_token } = await signIn("ada", "org-acme");
    const claims = await introspect(access_token);
    assertEquals(claims.org_id, "org-acme");
    assertEquals(claims.org_slug, "acme");
    assertEquals(claims.org_roles, ["editor"]);
    assertEquals(claims.permissions?.sort(), [
      "documents:read",
      "notes:write",
    ]);
  });

  it("keeps a refreshed credential in the organization it was issued for", async () => {
    const issued = await signIn("ada", "org-globex");
    tenant.signInAs("ada", { organizationId: "org-acme" });
    const refreshed = await token({
      grant_type: "refresh_token",
      refresh_token: issued.refresh_token!,
    });
    assertEquals(
      (await introspect(refreshed.access_token)).org_id,
      "org-globex",
    );
  });

  it("stops answering for an organization once the membership ends", async () => {
    await tenant.addUser({ id: "cy", username: "cy" });
    tenant.addMember("org-acme", "cy", { permissions: ["notes:write"] });
    const { access_token } = await signIn("cy", "org-acme");
    tenant.removeMember("org-acme", "cy");
    const claims = await introspect(access_token);
    assertFalse("org_id" in claims);
    assertEquals(claims.permissions, []);
  });

  it("issues no code when nobody is signed in", async () => {
    tenant.signInAs(null);
    const authorize = new URL(url("/api/oauth2/authorize"));
    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: APP.id,
      redirect_uri: REDIRECT,
      state: "s",
      code_challenge: await generateCodeChallenge(generateCodeVerifier()),
      code_challenge_method: "S256",
    }).toString();
    const response = await fetch(authorize, { redirect: "manual" });
    await response.body?.cancel();
    const location = response.headers.get("location");
    assertFalse(
      location && new URL(location).searchParams.has("code"),
      `answered ${response.status} ${location}`,
    );
  });

  it("serves UserInfo for the signed-in person", async () => {
    const { access_token } = await signIn("ada");
    const response = await fetch(url("/api/oauth2/userinfo"), {
      headers: { authorization: `Bearer ${access_token}` },
    });
    const claims = await response.json();
    assertEquals(claims.sub, "ada");
    assertEquals(claims.name, "Ada Lovelace");
    assertEquals(claims.email, "ada@example.com");
    assertEquals(claims.email_verified, true);
  });

  it("mints JWT access tokens a resource server verifies against its JWKS", async () => {
    const accessToken = await tenant.issueAccessToken({
      clientId: "mcp-client",
      userId: "ada",
      organizationId: "org-acme",
    });
    const reader = new JwksTokenReader<{ id: string }, unknown>({
      issuer: tenant.issuer,
      audience: MCP,
      getClient: (claims) => ({ id: claims.client_id! }),
    });
    const verified = await reader.getToken(accessToken);
    assert(verified, "the JWT did not verify against the tenant's JWKS");
    const claims = JSON.parse(atob(accessToken.split(".")[1]));
    assertEquals(claims.aud, MCP);
    assertEquals(claims.org_id, "org-acme");
    assertEquals(claims.permissions.sort(), ["documents:read", "notes:write"]);
  });

  describe("POST /api/check", () => {
    it("answers the credential's own scope when no resource is named", async () => {
      const { access_token } = await signIn("ada", "org-acme");
      const answer = await ask(access_token, "/api/check", {
        permissions: ["notes:write", "notes:delete"],
      });
      assertEquals(answer.status, 200);
      assertEquals(answer.body, {
        subject: "ada",
        resource: { type: "organization", id: "org-acme" },
        results: { "notes:write": true, "notes:delete": false },
      });
    });

    it("answers another organization the caller belongs to when named", async () => {
      const { access_token } = await signIn("ada", "org-acme");
      const answer = await ask(access_token, "/api/check", {
        permissions: "notes:delete",
        resource: { type: "organization", id: "org-globex" },
      });
      assertEquals(answer.body.results, { "notes:delete": true });
    });

    it("refuses an organization the caller does not belong to as not found", async () => {
      const { access_token } = await signIn("bob");
      const answer = await ask(access_token, "/api/check", {
        permissions: "notes:delete",
        resource: { type: "organization", id: "org-globex" },
      });
      assertEquals(answer.status, 404);
    });

    it("answers a resource from grants to the person or to an organization they belong to", async () => {
      const { access_token } = await signIn("bob");
      const direct = await ask(access_token, "/api/check", {
        permissions: ["documents:read", "documents:write"],
        resource: { type: "document", id: "doc-1" },
      });
      assertEquals(direct.body.results, {
        "documents:read": true,
        "documents:write": false,
      });
      const viaOrganization = await ask(access_token, "/api/check", {
        permissions: ["documents:write"],
        resource: { type: "document", id: "doc-2" },
      });
      assertEquals(viaOrganization.body.results, { "documents:write": true });
    });

    it("does not add organization permissions to a resource answer", async () => {
      const { access_token } = await signIn("ada", "org-acme");
      const answer = await ask(access_token, "/api/check", {
        permissions: ["notes:write"],
        resource: { type: "document", id: "doc-1" },
      });
      assertEquals(answer.body.results, { "notes:write": false });
    });

    it("refuses an unregistered resource type rather than guessing", async () => {
      const { access_token } = await signIn("ada");
      const answer = await ask(access_token, "/api/check", {
        permissions: ["documents:read"],
        resource: { type: "invoice", id: "inv-1" },
      });
      assertEquals(answer.status, 400);
    });

    it("refuses a request with no bearer token", async () => {
      const response = await fetch(url("/api/check"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ permissions: ["documents:read"] }),
      });
      await response.body?.cancel();
      assertEquals(response.status, 401);
    });
  });

  describe("POST /api/check/batch", () => {
    it("answers each candidate id as /api/check would", async () => {
      const { access_token } = await signIn("bob");
      const answer = await ask(access_token, "/api/check/batch", {
        permissions: ["documents:read"],
        resource: { type: "document", ids: ["doc-1", "doc-3"] },
      });
      assertEquals(answer.status, 200);
      assertEquals(answer.body, {
        subject: "bob",
        resource: { type: "document" },
        results: {
          "doc-1": { "documents:read": true },
          "doc-3": { "documents:read": false },
        },
      });
    });

    it("refuses more than a hundred candidates", async () => {
      const { access_token } = await signIn("bob");
      const answer = await ask(access_token, "/api/check/batch", {
        permissions: ["documents:read"],
        resource: {
          type: "document",
          ids: Array.from({ length: 101 }, (_, i) => `doc-${i}`),
        },
      });
      assertEquals(answer.status, 400);
    });
  });
});
