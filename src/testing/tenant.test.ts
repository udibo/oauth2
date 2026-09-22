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

  async function authorizeWith(
    params: Record<string, string>,
  ): Promise<URL> {
    const authorize = new URL(url("/api/oauth2/authorize"));
    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: APP.id,
      redirect_uri: REDIRECT,
      state: "s",
      code_challenge: await generateCodeChallenge(generateCodeVerifier()),
      code_challenge_method: "S256",
      ...params,
    }).toString();
    const response = await fetch(authorize, { redirect: "manual" });
    await response.body?.cancel();
    return new URL(response.headers.get("location")!);
  }

  it("refuses an organization parameter naming one the person has not joined", async () => {
    tenant.signInAs("bob");
    const callback = await authorizeWith({ organization: "globex" });
    assertEquals(callback.searchParams.get("error"), "invalid_request");
    assertFalse(callback.searchParams.has("code"));
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
});
