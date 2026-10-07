import {
  assert,
  assertEquals,
  assertFalse,
  assertRejects,
  assertThrows,
} from "@std/assert";
import { afterAll, beforeAll, describe, it } from "@std/testing/bdd";
import { FakeTime } from "@std/testing/time";

import { JwksTokenReader } from "../server/jwks-token-reader.ts";
import { encodeBasicAuth } from "../utils/basic-auth.ts";
import { generateCodeChallenge, generateCodeVerifier } from "../utils/pkce.ts";
import { createFakeTenant, type FakeTenant } from "./tenant.ts";

const APP = { id: "app", secret: "app-secret" };
const PARTNER = { id: "partner", secret: "partner-secret" };
const REPORTER = { id: "reporter", secret: "reporter-secret" };
const JWT_REPORTER = { id: "jwt-reporter", secret: "jwt-reporter-secret" };
const ORGANIZATIONS_READ = "identity:organizations:read";
const ORGANIZATIONS_WRITE = "identity:organizations:write";
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
    await tenant.addClient({
      id: REPORTER.id,
      secret: REPORTER.secret,
      grants: ["client_credentials"],
      scopes: [ORGANIZATIONS_READ, ORGANIZATIONS_WRITE, "identity:users:read"],
      machinePermissions: ["resource_grants.read"],
    });
    await tenant.addClient({
      id: JWT_REPORTER.id,
      secret: JWT_REPORTER.secret,
      grants: ["client_credentials"],
      scopes: [ORGANIZATIONS_READ],
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

  async function machineToken(
    scope: string,
    client = REPORTER,
  ): Promise<
    {
      status: number;
      body: { access_token?: string; scope?: string; error?: string };
    }
  > {
    const response = await fetch(url("/api/oauth2/token"), {
      method: "POST",
      headers: { authorization: encodeBasicAuth(client.id, client.secret) },
      body: new URLSearchParams({ grant_type: "client_credentials", scope }),
    });
    return { status: response.status, body: await response.json() };
  }

  async function grantsOn(
    id: string,
  ): Promise<
    {
      roleId: string | null;
      builtInRole: string | null;
      roleSlug: string;
      roleName: string;
    }[]
  > {
    const { body } = await machineToken(ORGANIZATIONS_READ);
    const response = await fetch(
      url(`/api/resource-grants?type=document&id=${id}`),
      { headers: { authorization: `Bearer ${body.access_token}` } },
    );
    assertEquals(response.status, 200, await response.clone().text());
    return (await response.json()).grants;
  }

  it("refuses to register a machine client that states no scope allowlist", async () => {
    await assertRejects(
      () =>
        tenant.addClient({
          id: "unbounded",
          secret: "unbounded-secret",
          grants: ["client_credentials"],
        }),
      Error,
      "scopes",
    );
  });

  it("issues a machine token the allowlisted scopes its vocabulary has, and none it lacks", async () => {
    const both = await machineToken(
      `${ORGANIZATIONS_READ} ${ORGANIZATIONS_WRITE}`,
    );
    assertEquals(both.status, 200, JSON.stringify(both.body));
    assertEquals(
      both.body.scope,
      `${ORGANIZATIONS_READ} ${ORGANIZATIONS_WRITE}`,
    );
    const outside = await machineToken("identity:users:read");
    assertEquals(outside.status, 400);
    assertEquals(outside.body.error, "invalid_scope");
  });

  it("mints a JWT naming the client as its subject for a machine client that opted in", async () => {
    const issued = await machineToken(ORGANIZATIONS_READ, JWT_REPORTER);
    assertEquals(issued.status, 200, JSON.stringify(issued.body));
    const accessToken = issued.body.access_token!;
    const reader = new JwksTokenReader<{ id: string }, unknown>({
      issuer: tenant.issuer,
      audience: MCP,
      getClient: (claims) => ({ id: claims.client_id! }),
    });
    assert(
      await reader.getToken(accessToken),
      "the machine JWT did not verify against the tenant's JWKS",
    );
    const claims = JSON.parse(atob(accessToken.split(".")[1]));
    assertEquals(claims.sub, JWT_REPORTER.id);
    assertEquals(claims.client_id, JWT_REPORTER.id);
    assertEquals(claims.scope, ORGANIZATIONS_READ);
    assertFalse(
      "permissions" in claims,
      "a machine token holds no permissions",
    );
    assertFalse("username" in claims, "a machine token names no person");
  });

  it("refuses a machine token an OIDC scope even when its allowlist names one", async () => {
    const oidcListed = { id: "oidc-listed", secret: "oidc-listed-secret" };
    await tenant.addClient({
      ...oidcListed,
      grants: ["client_credentials"],
      scopes: [ORGANIZATIONS_READ, "openid"],
    });
    const refused = await machineToken("openid", oidcListed);
    assertEquals(refused.status, 400, JSON.stringify(refused.body));
    assertEquals(refused.body.error, "invalid_scope");
  });

  it("refuses client_credentials to a public client as a failed authentication, before asking whether it may use the grant", async () => {
    await tenant.addClient({
      id: "public-interactive",
      redirectUris: ["http://public.localhost/callback"],
    });
    const response = await fetch(url("/api/oauth2/token"), {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: "public-interactive",
        scope: ORGANIZATIONS_READ,
      }),
    });
    const body = await response.json();
    assertEquals(response.status, 401, JSON.stringify(body));
    assertEquals(body.error, "invalid_client");
  });

  it("answers a public client introspecting even its own token that it is inactive", async () => {
    await tenant.addClient({
      id: "public-app",
      redirectUris: ["http://public.localhost/callback"],
    });
    const accessToken = await tenant.issueAccessToken({
      clientId: "public-app",
      userId: "ada",
    });
    const response = await fetch(url("/api/oauth2/introspect"), {
      method: "POST",
      body: new URLSearchParams({
        client_id: "public-app",
        token: accessToken,
      }),
    });
    assertEquals(response.status, 200);
    assertEquals(await response.json(), { active: false });
  });

  it("lists the grants on one resource in role-name order, compared by locale", async () => {
    tenant.defineOrganizationRole({ slug: "zeta-reviewer", name: "Zeta" });
    tenant.defineOrganizationRole({ slug: "alpha-reader", name: "alpha" });
    tenant.grant({
      resource: { type: "document", id: "doc-ordered" },
      subject: { type: "user", id: "ada" },
      permissions: ["documents:comment"],
      role: "zeta-reviewer",
    });
    tenant.grant({
      resource: { type: "document", id: "doc-ordered" },
      subject: { type: "user", id: "bob" },
      permissions: ["documents:read"],
      role: "alpha-reader",
    });
    const listed = await grantsOn("doc-ordered");
    assertEquals(listed.map((grant) => grant.roleName), ["alpha", "Zeta"]);
  });

  it("lists a grant of a built-in tier as one, with no role id", async () => {
    tenant.grant({
      resource: { type: "document", id: "doc-5" },
      subject: { type: "user", id: "bob" },
      permissions: ["documents:read"],
      role: "member",
    });
    const [held] = await grantsOn("doc-5");
    assertEquals(held.builtInRole, "member");
    assertEquals(held.roleId, null);
    assertEquals(held.roleSlug, "member");
    assertEquals(held.roleName, "Member");
  });

  it("lists a grant under the role it names, or under a slug built from its permissions, one id per role", async () => {
    tenant.defineOrganizationRole({ slug: "reviewer", name: "Reviewer" });
    for (const id of ["doc-3", "doc-4"]) {
      tenant.grant({
        resource: { type: "document", id },
        subject: { type: "user", id: "bob" },
        permissions: ["documents:read", "documents:comment"],
        role: "reviewer",
      });
    }
    const [derived] = await grantsOn("doc-1");
    assertEquals(derived.roleSlug, "documents-read");
    assertEquals(derived.roleName, "documents-read");
    const [named] = await grantsOn("doc-3");
    assertEquals(named.roleSlug, "reviewer");
    assertEquals(named.roleName, "Reviewer");
    const [sameRole] = await grantsOn("doc-4");
    assertEquals(sameRole.roleId, named.roleId);
    assert(derived.roleId !== named.roleId, "each role has an id of its own");
  });

  it("lists a grant of a defined role under that role's own id", async () => {
    const roleId = tenant.defineOrganizationRole({
      slug: "document-reviewer",
      name: "Document reviewer",
    });
    tenant.grant({
      resource: { type: "document", id: "doc-reviewed" },
      subject: { type: "user", id: "bob" },
      permissions: ["documents:read"],
      role: "document-reviewer",
    });
    const [listed] = await grantsOn("doc-reviewed");
    assertEquals(listed.roleId, roleId);
    assertEquals(listed.roleName, "Document reviewer");
  });

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

describe("createFakeTenant's organization and account APIs", () => {
  const DAY_MS = 24 * 60 * 60 * 1000;
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
      id: PARTNER.id,
      secret: PARTNER.secret,
      redirectUris: [REDIRECT],
      type: "third-party",
    });
  });

  afterAll(async () => {
    await server.shutdown();
  });

  const url = (path: string) => `${tenant.issuer}${path}`;

  async function addPerson(
    fields: Partial<Parameters<FakeTenant["addUser"]>[0]> = {},
  ): Promise<string> {
    const id = crypto.randomUUID();
    await tenant.addUser({
      id,
      username: id,
      email: `${id}@example.com`,
      ...fields,
    });
    return id;
  }

  function mint(userId: string, organizationId?: string): Promise<string> {
    return tenant.issueAccessToken({
      clientId: APP.id,
      userId,
      organizationId,
    });
  }

  interface Browser {
    cookie?: string;
  }

  async function authorize(client = APP, browser?: Browser): Promise<string> {
    return (await authorizeTokens(client, browser)).access_token;
  }

  async function authorizeTokens(
    client = APP,
    browser?: Browser,
  ): Promise<{ access_token: string; refresh_token?: string }> {
    const verifier = generateCodeVerifier();
    const request = new URL(url("/api/oauth2/authorize"));
    request.search = new URLSearchParams({
      response_type: "code",
      client_id: client.id,
      redirect_uri: REDIRECT,
      scope: "openid offline_access",
      state: "s",
      code_challenge: await generateCodeChallenge(verifier),
      code_challenge_method: "S256",
    }).toString();
    const redirect = await fetch(request, {
      redirect: "manual",
      headers: browser?.cookie ? { cookie: browser.cookie } : {},
    });
    await redirect.body?.cancel();
    const setCookie = redirect.headers.get("set-cookie");
    if (browser && setCookie) browser.cookie = setCookie.split(";")[0];
    const code = new URL(redirect.headers.get("location")!).searchParams.get(
      "code",
    );
    assert(code, `authorize answered ${redirect.status} without a code`);
    const response = await fetch(url("/api/oauth2/token"), {
      method: "POST",
      headers: { authorization: encodeBasicAuth(client.id, client.secret) },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT,
        code_verifier: verifier,
      }),
    });
    assertEquals(response.status, 200);
    return await response.json();
  }

  async function call<T = Record<string, unknown>>(
    accessToken: string,
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ status: number; body: T }> {
    const headers: Record<string, string> = {
      authorization: `Bearer ${accessToken}`,
    };
    if (body !== undefined) headers["content-type"] = "application/json";
    const response = await fetch(url(path), {
      method,
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await response.text();
    return {
      status: response.status,
      body: (text ? JSON.parse(text) : null) as T,
    };
  }

  async function createOrganization(
    accessToken: string,
    name: string,
  ): Promise<string> {
    const created = await call<{ id: string }>(
      accessToken,
      "POST",
      "/api/organizations",
      { name, slug: `${name.toLowerCase()}-${crypto.randomUUID()}` },
    );
    assertEquals(created.status, 201);
    return created.body.id;
  }

  interface Session {
    id: string;
    current: boolean;
    userAgent: string | null;
    ipAddress: string | null;
  }

  async function sessionsOf(accessToken: string): Promise<Session[]> {
    const reply = await call<{ sessions: Session[] }>(
      accessToken,
      "GET",
      "/api/account/sessions",
    );
    assertEquals(reply.status, 200);
    return reply.body.sessions;
  }

  it("gives a membership seeded without roles the member tier", async () => {
    const person = await addPerson();
    const organizationId = crypto.randomUUID();
    tenant.addOrganization({ id: organizationId, slug: `o-${person}` });
    const token = await mint(person);
    for (const membership of [undefined, { roles: [] }]) {
      tenant.addMember(organizationId, person, membership);
      const reply = await call<{ memberships: { roles: string[] }[] }>(
        token,
        "GET",
        "/api/memberships",
      );
      assertEquals(reply.body.memberships.map((entry) => entry.roles), [[
        "member",
      ]]);
    }
  });

  it("starts a login session for every sign-in, so each browser is a device of its own", async () => {
    const person = await addPerson();
    tenant.signInAs(person);
    const first = await authorize(APP, {});
    const second = await authorize(APP, {});
    const third = await authorize();
    const listed = await sessionsOf(third);
    assertEquals(listed.length, 3);
    for (const token of [first, second, third]) {
      assertEquals(
        (await call(token, "GET", "/api/account")).status,
        200,
        "a sign-in in another browser revoked this one's credential",
      );
    }
    const currents = await Promise.all(
      [first, second, third].map(async (token) =>
        (await sessionsOf(token)).find((session) => session.current)?.id
      ),
    );
    assertEquals(new Set(currents).size, 3);
  });

  it("continues the login session of a browser that sends its cookie back while it is the chosen person's", async () => {
    const ada = await addPerson();
    const bob = await addPerson();
    const browser: Browser = {};
    tenant.signInAs(ada);
    const adaFirst = await authorize(APP, browser);
    assert(browser.cookie, "a sign-in set no login-session cookie");
    const adaAgain = await authorize(APP, browser);
    const adaSessions = await sessionsOf(adaAgain);
    assertEquals(adaSessions.length, 1);
    assertEquals(
      (await call(adaFirst, "GET", "/api/account")).status,
      401,
      "the same browser signed in again and left its earlier credential live",
    );

    tenant.signInAs(bob);
    const asBob = await authorize(APP, browser);
    assertEquals((await sessionsOf(asBob)).length, 1);
    assertEquals(
      (await sessionsOf(adaAgain)).map((session) => session.id),
      adaSessions.map((session) => session.id),
      "another person's sign-in in this browser ended or joined ada's session",
    );

    tenant.signInAs(ada);
    const adaReturns = await authorize(APP, browser);
    const returned = await sessionsOf(adaReturns);
    assertEquals(returned.length, 2);
    assertFalse(
      returned.find((session) => session.current)?.id === adaSessions[0].id,
      "a cookie naming bob's session continued ada's",
    );
  });

  it("starts a new login session when the browser's session has ended", async () => {
    const person = await addPerson();
    const browser: Browser = {};
    tenant.signInAs(person);
    const ended = await authorize(APP, browser);
    const [endedSession] = await sessionsOf(ended);
    const elsewhere = await authorize();
    const revoked = await call(
      elsewhere,
      "DELETE",
      `/api/account/sessions/${endedSession.id}`,
    );
    assertEquals(revoked.status, 204);
    const again = await authorize(APP, browser);
    const listed = await sessionsOf(again);
    assertEquals(listed.length, 2);
    assertFalse(listed.some((session) => session.id === endedSession.id));
  });

  it("names a cookie Secure only on an https issuer", async () => {
    const secure = await createFakeTenant({ issuer: "https://tenant.test" });
    await secure.addClient({
      id: APP.id,
      secret: APP.secret,
      redirectUris: [REDIRECT],
    });
    await secure.addUser({ id: "ada", username: "ada" });
    secure.signInAs("ada");
    const request = new URL("https://tenant.test/api/oauth2/authorize");
    request.search = new URLSearchParams({
      response_type: "code",
      client_id: APP.id,
      redirect_uri: REDIRECT,
      scope: "openid",
      state: "s",
      code_challenge: await generateCodeChallenge(generateCodeVerifier()),
      code_challenge_method: "S256",
    }).toString();
    const onHttps = await secure.fetch(new Request(request));
    await onHttps.body?.cancel();
    tenant.signInAs(await addPerson());
    const onHttp = await fetch(
      url(`/api/oauth2/authorize?${request.searchParams}`),
      { redirect: "manual" },
    );
    await onHttp.body?.cancel();
    assertEquals(
      onHttps.headers.get("set-cookie")?.split("; ").slice(1),
      ["Path=/", "HttpOnly", "SameSite=Lax", "Secure"],
    );
    assertEquals(
      onHttp.headers.get("set-cookie")?.split("; ").slice(1),
      ["Path=/", "HttpOnly", "SameSite=Lax"],
    );
  });

  it("reports each browser's device, and revokes a browser's earlier credential when it signs in again", async () => {
    const person = await addPerson();
    const phone: Browser = {};
    tenant.signInAs(person, {
      userAgent: "Phone Browser",
      ipAddress: "192.0.2.10",
    });
    const onPhone = await authorize(APP, phone);
    const againOnPhone = await authorize(APP, phone);
    tenant.signInAs(person, { userAgent: "Laptop Browser" });
    const onLaptop = await authorize();

    const listed = await sessionsOf(onLaptop);
    assertEquals(listed.map((session) => session.userAgent), [
      "Laptop Browser",
      "Phone Browser",
    ]);
    assertEquals(listed.map((session) => session.ipAddress), [
      null,
      "192.0.2.10",
    ]);
    assertEquals(
      (await sessionsOf(againOnPhone)).find((session) => session.current)?.id,
      listed[1].id,
    );
    const replaced = await call(onPhone, "GET", "/api/account/sessions");
    assertEquals(
      replaced.status,
      401,
      "a second sign-in in the same browser left the first credential live",
    );
  });

  async function revoke(token: string, client = APP): Promise<void> {
    const response = await fetch(url("/api/oauth2/revoke"), {
      method: "POST",
      headers: { authorization: encodeBasicAuth(client.id, client.secret) },
      body: new URLSearchParams({ token }),
    });
    await response.body?.cancel();
    assertEquals(response.status, 200);
  }

  it("keeps a third-party app's credentials apart from the login session they came from", async () => {
    const person = await addPerson();
    const phoneBrowser: Browser = {};
    tenant.signInAs(person, { userAgent: "Phone Browser" });
    const firstParty = await authorize(APP, phoneBrowser);
    const thirdParty = await authorize(PARTNER, phoneBrowser);
    const [phone] = await sessionsOf(firstParty);
    assertEquals(
      (await sessionsOf(thirdParty)).find((session) => session.current)?.id,
      phone.id,
      "a third-party credential names the session it came from as current",
    );
    const firstPartyAgain = await authorize(APP, phoneBrowser);
    assertEquals(
      (await call(firstParty, "GET", "/api/account")).status,
      401,
      "a first-party sign-in in the same browser left its predecessor live",
    );
    assertEquals(
      (await call(thirdParty, "GET", "/api/account")).status,
      200,
      "a first-party sign-in revoked a third-party credential",
    );

    await revoke(thirdParty, PARTNER);
    assertEquals(
      (await sessionsOf(firstPartyAgain)).map((session) => session.id),
      [phone.id],
      "revoking a third-party credential ended the login session",
    );

    const partnerAgain = await authorize(PARTNER, phoneBrowser);
    tenant.signInAs(person, { userAgent: "Laptop Browser" });
    const onLaptop = await authorize();
    const ended = await call(
      onLaptop,
      "DELETE",
      `/api/account/sessions/${phone.id}`,
    );
    assertEquals(ended.status, 204);
    assertEquals(
      (await call(firstPartyAgain, "GET", "/api/account")).status,
      401,
    );
    assertEquals(
      (await call(partnerAgain, "GET", "/api/account")).status,
      200,
      "ending the login session revoked a third-party credential",
    );
  });

  it("leaves a login session alone when another app presents one of its tokens", async () => {
    const person = await addPerson();
    tenant.signInAs(person);
    const issued = await authorizeTokens();
    await revoke(issued.refresh_token!, PARTNER);
    const refreshed = await fetch(url("/api/oauth2/token"), {
      method: "POST",
      headers: { authorization: encodeBasicAuth(PARTNER.id, PARTNER.secret) },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: issued.refresh_token!,
      }),
    });
    await refreshed.body?.cancel();
    assertFalse(refreshed.ok, "another app refreshed this app's token");
    assertEquals((await sessionsOf(issued.access_token)).length, 1);
  });

  it("ends the login session when a replayed refresh token revokes its family", async () => {
    const person = await addPerson();
    tenant.signInAs(person, { userAgent: "Phone Browser" });
    const issued = await authorizeTokens();
    tenant.signInAs(person, { userAgent: "Laptop Browser" });
    const onLaptop = await authorize();
    const rotated = await fetch(url("/api/oauth2/token"), {
      method: "POST",
      headers: { authorization: encodeBasicAuth(APP.id, APP.secret) },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: issued.refresh_token!,
      }),
    });
    assertEquals(rotated.status, 200);
    const successor = await rotated.json();
    assertEquals((await sessionsOf(onLaptop)).length, 2);

    const replayed = await fetch(url("/api/oauth2/token"), {
      method: "POST",
      headers: { authorization: encodeBasicAuth(APP.id, APP.secret) },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: issued.refresh_token!,
      }),
    });
    await replayed.body?.cancel();
    assertEquals(replayed.status, 400);
    assertEquals(
      (await call(successor.access_token, "GET", "/api/account")).status,
      401,
    );
    assertEquals(
      (await sessionsOf(onLaptop)).map((session) => session.userAgent),
      ["Laptop Browser"],
      "a revoked family left its login session listed",
    );
  });

  it("signs the person in again when their login was ended from another device", async () => {
    const person = await addPerson();
    tenant.signInAs(person, { userAgent: "Phone Browser" });
    const onPhone = await authorize();
    const [phoneSession] = await sessionsOf(onPhone);
    tenant.signInAs(person, { userAgent: "Laptop Browser" });
    const onLaptop = await authorize();
    const ended = await call(
      onLaptop,
      "DELETE",
      `/api/account/sessions/${phoneSession.id}`,
    );
    assertEquals(ended.status, 204);

    tenant.signInAs(person, { userAgent: "Phone Browser" });
    const listed = await sessionsOf(await authorize());
    assertEquals(listed.length, 2);
    assertFalse(listed.some((session) => session.id === phoneSession.id));
  });

  it("gives a minted access token no login session, so it cannot sign out the others", async () => {
    const person = await addPerson();
    tenant.signInAs(person);
    await authorize();
    const minted = await mint(person);
    const listed = await sessionsOf(minted);
    assertEquals(listed.map((session) => session.current), [false]);
    const refused = await call<{ reason?: string }>(
      minted,
      "POST",
      "/api/account/sessions/revoke-others",
    );
    assertEquals(refused.status, 409);
    assertEquals(refused.body.reason, "current_session_required");
  });

  it("answers the metadata bucket a person was seeded with", async () => {
    const person = await addPerson({ userMetadata: { plan: "trial" } });
    const reply = await call(await mint(person), "GET", "/api/account");
    assertEquals(reply.body, { userMetadata: { plan: "trial" } });
  });

  it("refuses a metadata bucket larger than sixteen kilobytes", async () => {
    const person = await addPerson();
    const reply = await call(await mint(person), "PATCH", "/api/account", {
      userMetadata: { notes: "x".repeat(16 * 1024) },
    });
    assertEquals(reply.status, 400);
  });

  it("offers an organization role the tenant defined, under the name it was given", async () => {
    tenant.defineOrganizationRole({ slug: "reviewer", name: "Reviewer" });
    const owner = await addPerson();
    const invitee = await addPerson();
    const ownerToken = await mint(owner);
    const organizationId = await createOrganization(ownerToken, "Reviewed");
    const roles = await call<{ slug: string; name: string }[]>(
      ownerToken,
      "GET",
      `/api/organizations/${organizationId}/member-roles`,
    );
    assert(
      roles.body.some((role) =>
        role.slug === "reviewer" && role.name === "Reviewer"
      ),
    );
    const offered = await call(
      ownerToken,
      "POST",
      `/api/organizations/${organizationId}/invitations`,
      { email: `${invitee}@example.com`, role: "reviewer" },
    );
    assertEquals(offered.status, 201);
    const waiting = await call<{ offers: { roleName: string }[] }>(
      await mint(invitee),
      "GET",
      "/api/organizations/offers",
    );
    assertEquals(waiting.body.offers.map((offer) => offer.roleName), [
      "Reviewer",
    ]);
  });

  it("refuses to define a role that shadows a built-in tier", () => {
    let thrown: unknown;
    try {
      tenant.defineOrganizationRole({ slug: "owner" });
    } catch (error) {
      thrown = error;
    }
    assert(thrown instanceof Error, "defining owner did not throw");
  });

  it("pages the members listing twenty at a time by default", async () => {
    const organizationId = crypto.randomUUID();
    tenant.addOrganization({
      id: organizationId,
      slug: `big-${organizationId}`,
    });
    const people = await Promise.all(
      Array.from({ length: 25 }, () => addPerson()),
    );
    for (const person of people) tenant.addMember(organizationId, person);
    const token = await mint(people[0], organizationId);
    interface Page {
      data: { userId: string }[];
      cursors: { next: string | null; prev: string | null };
      hasMore: boolean;
    }
    const pageAt = (cursor?: string | null) =>
      call<Page>(
        token,
        "GET",
        `/api/organizations/${organizationId}/members${
          cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""
        }`,
      );
    const first = await pageAt();
    assertEquals(first.body.data.length, 20);
    assertEquals(first.body.hasMore, true);
    assertEquals(first.body.cursors.prev, null);
    const second = await pageAt(first.body.cursors.next);
    assertEquals(second.body.data.length, 5);
    assertEquals(second.body.hasMore, false);
    assertEquals(
      [...first.body.data, ...second.body.data].map((row) => row.userId)
        .sort(),
      [...people].sort(),
    );
    const back = await pageAt(second.body.cursors.prev);
    assertEquals(back.body.data, first.body.data);
  });

  it("withdraws its offers when an organization is deleted", async () => {
    const owner = await addPerson();
    const invitee = await addPerson();
    const ownerToken = await mint(owner);
    const organizationId = await createOrganization(ownerToken, "Doomed");
    const offered = await call<{ membership: { id: string } }>(
      ownerToken,
      "POST",
      `/api/organizations/${organizationId}/invitations`,
      { email: `${invitee}@example.com`, role: "member" },
    );
    const deleted = await call(
      ownerToken,
      "DELETE",
      `/api/organizations/${organizationId}`,
    );
    assertEquals(deleted.status, 204);
    const inviteeToken = await mint(invitee);
    const waiting = await call<{ offers: unknown[] }>(
      inviteeToken,
      "GET",
      "/api/organizations/offers",
    );
    assertEquals(waiting.body.offers, []);
    const accepted = await call<{ status: string }>(
      inviteeToken,
      "POST",
      `/api/organizations/offers/${offered.body.membership.id}/accept`,
    );
    assertEquals(accepted.body.status, "invalid");
  });

  it("stores a return_to on a registered origin or on the tenant's own host", async () => {
    const ownerToken = await mint(await addPerson());
    const organizationId = await createOrganization(ownerToken, "Returning");
    for (
      const returnTo of [
        `${new URL(REDIRECT).origin}/welcome`,
        "/organization-invite",
      ]
    ) {
      const offered = await call<{ invitation: { returnTo: string } }>(
        ownerToken,
        "POST",
        `/api/organizations/${organizationId}/invitations`,
        {
          email: `${crypto.randomUUID()}@example.com`,
          role: "member",
          return_to: returnTo,
        },
      );
      assertEquals(offered.status, 201);
      assertEquals(offered.body.invitation.returnTo, returnTo);
    }
  });

  it("refuses an invitation listing filtered by a status it does not know", async () => {
    const ownerToken = await mint(await addPerson());
    const organizationId = await createOrganization(ownerToken, "Filtered");
    const reply = await call(
      ownerToken,
      "GET",
      `/api/organizations/${organizationId}/invitations?status=accepted`,
    );
    assertEquals(reply.status, 400);
  });

  it("answers an invitation older than seven days as expired", async () => {
    const address = `${crypto.randomUUID()}@example.com`;
    const ownerToken = await mint(await addPerson());
    const organizationId = await createOrganization(ownerToken, "Expiring");
    const offered = await call<{ invitation: { id: string } }>(
      ownerToken,
      "POST",
      `/api/organizations/${organizationId}/invitations`,
      { email: address, role: "member" },
    );
    const holder = await addPerson({ email: address });
    using _later = new FakeTime(Date.now() + 8 * DAY_MS);
    const holderToken = await mint(holder);
    const waiting = await call<{ offers: { id: string }[] }>(
      holderToken,
      "GET",
      "/api/organizations/offers",
    );
    assertEquals(waiting.body.offers, [], "an expired invitation was offered");
    const accepted = await call<{ status: string }>(
      holderToken,
      "POST",
      `/api/organizations/offers/${offered.body.invitation.id}/accept`,
    );
    assertEquals(accepted.body.status, "expired");
  });

  it("refuses to link an account to a person it does not know", () => {
    let thrown: unknown;
    try {
      tenant.linkAccount("nobody", { provider: "github" });
    } catch (error) {
      thrown = error;
    }
    assert(thrown instanceof Error, "linking to nobody did not throw");
  });

  async function permitted(
    accessToken: string,
    permission: string,
  ): Promise<boolean> {
    const reply = await call<{ results: Record<string, boolean> }>(
      accessToken,
      "POST",
      "/api/check",
      { permissions: [permission] },
    );
    assertEquals(reply.status, 200);
    return reply.body.results[permission];
  }

  async function grantAppRole(
    managerToken: string,
    organizationId: string,
    userId: string,
    roleId: string,
  ): Promise<void> {
    const granted = await call(
      managerToken,
      "POST",
      `/api/organizations/${organizationId}/members/${userId}/roles`,
      { roleId },
    );
    assertEquals(granted.status, 201, JSON.stringify(granted.body));
  }

  it("keeps a defined role's id across redefinition, which changes what holders are granted", async () => {
    const slug = `auditor-${crypto.randomUUID()}`;
    const permission = `audits:read-${crypto.randomUUID()}`;
    const roleId = tenant.defineOrganizationRole({ slug, name: "Auditor" });
    const owner = await addPerson();
    const member = await addPerson();
    const organizationId = await createOrganization(
      await mint(owner),
      "Audited",
    );
    tenant.addMember(organizationId, member);
    await grantAppRole(await mint(owner), organizationId, member, roleId);
    const memberToken = await mint(member, organizationId);
    assertFalse(await permitted(memberToken, permission));

    assertEquals(
      tenant.defineOrganizationRole({ slug, permissions: [permission] }),
      roleId,
    );
    assert(
      await permitted(memberToken, permission),
      "a holder kept the role's earlier permissions",
    );
    const roles = await call<{ id?: string; slug: string; name: string }[]>(
      await mint(owner),
      "GET",
      `/api/organizations/${organizationId}/member-roles`,
    );
    assertEquals(
      roles.body.filter((role) => role.slug === slug),
      [{ id: roleId, slug, name: slug }],
    );
  });

  it("defines a role under the id it is given, and refuses an id another role holds", () => {
    const id = crypto.randomUUID();
    assertEquals(
      tenant.defineOrganizationRole({ slug: `given-${id}`, id }),
      id,
    );
    assertThrows(
      () => tenant.defineOrganizationRole({ slug: `taken-${id}`, id }),
      Error,
      id,
    );
  });

  it("answers a granted role's permissions for a credential issued in that organization, and no other", async () => {
    const permission = `ledgers:close-${crypto.randomUUID()}`;
    const roleId = tenant.defineOrganizationRole({
      slug: `closer-${crypto.randomUUID()}`,
      permissions: [permission],
    });
    const owner = await addPerson();
    const member = await addPerson();
    const ownerToken = await mint(owner);
    const here = await createOrganization(ownerToken, "Here");
    const there = await createOrganization(ownerToken, "There");
    tenant.addMember(here, member);
    tenant.addMember(there, member);
    await grantAppRole(ownerToken, here, member, roleId);
    assert(await permitted(await mint(member, here), permission));
    assertFalse(await permitted(await mint(member, there), permission));
    assertFalse(await permitted(await mint(member), permission));
  });

  it("ends the application roles a membership held when removeMember ends it", async () => {
    const permission = `boards:pin-${crypto.randomUUID()}`;
    const roleId = tenant.defineOrganizationRole({
      slug: `pinner-${crypto.randomUUID()}`,
      permissions: [permission],
    });
    const owner = await addPerson();
    const member = await addPerson();
    const ownerToken = await mint(owner);
    const organizationId = await createOrganization(ownerToken, "Pinned");
    tenant.addMember(organizationId, member);
    await grantAppRole(ownerToken, organizationId, member, roleId);
    tenant.removeMember(organizationId, member);
    tenant.addMember(organizationId, member);
    assertFalse(
      await permitted(await mint(member, organizationId), permission),
      "a role outlived the membership removeMember ended",
    );
    const held = await call<unknown[]>(
      ownerToken,
      "GET",
      `/api/organizations/${organizationId}/members/${member}/roles`,
    );
    assertEquals(held.body, []);
  });

  it("ends the permissions a membership was seeded with when a manager revokes the last of it", async () => {
    const permission = `rotas:edit-${crypto.randomUUID()}`;
    const owner = await addPerson();
    const member = await addPerson();
    const ownerToken = await mint(owner);
    const organizationId = await createOrganization(ownerToken, "Rota");
    tenant.addMember(organizationId, member, { permissions: [permission] });
    assert(await permitted(await mint(member, organizationId), permission));
    const revoked = await call(
      ownerToken,
      "DELETE",
      `/api/organizations/${organizationId}/members/${member}/member`,
    );
    assertEquals(revoked.status, 204);
    const offered = await call<{ membership: { id: string } }>(
      ownerToken,
      "POST",
      `/api/organizations/${organizationId}/invitations`,
      { email: `${member}@example.com`, role: "member" },
    );
    assertEquals(offered.status, 201);
    const memberToken = await mint(member);
    const accepted = await call<{ status: string }>(
      memberToken,
      "POST",
      `/api/organizations/offers/${offered.body.membership.id}/accept`,
    );
    assertEquals(accepted.body.status, "accepted");
    assertFalse(
      await permitted(await mint(member, organizationId), permission),
      "rejoining restored what the ended membership was seeded with",
    );
  });

  it("forgets an organization's application roles when it is deleted", async () => {
    const permission = `archives:seal-${crypto.randomUUID()}`;
    const roleId = tenant.defineOrganizationRole({
      slug: `sealer-${crypto.randomUUID()}`,
      permissions: [permission],
    });
    const owner = await addPerson();
    const ownerToken = await mint(owner);
    const organizationId = await createOrganization(ownerToken, "Sealed");
    await grantAppRole(ownerToken, organizationId, owner, roleId);
    const deleted = await call(
      ownerToken,
      "DELETE",
      `/api/organizations/${organizationId}`,
    );
    assertEquals(deleted.status, 204);
    tenant.addOrganization({ id: organizationId, slug: `sealed-${owner}` });
    tenant.addMember(organizationId, owner);
    assertFalse(
      await permitted(await mint(owner, organizationId), permission),
      "a deleted organization's role came back with an organization of its id",
    );
  });
});
