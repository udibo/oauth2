import { afterAll, assert, beforeAll, describe, expect, it } from "vitest";
import { serve, type TestServer } from "../_test_server.ts";
import { FakeTime } from "../_test_fake-time.ts";
import { rejection, thrown } from "../_test_assert.ts";
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
  let server: TestServer;

  beforeAll(async () => {
    server = await serve((request) => tenant.fetch(request));
    tenant = await createFakeTenant({ issuer: server.origin });
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
    expect(response.status, await response.clone().text()).toStrictEqual(200);
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
  ): Promise<{
    status: number;
    body: { access_token?: string; scope?: string; error?: string };
  }> {
    const response = await fetch(url("/api/oauth2/token"), {
      method: "POST",
      headers: { authorization: encodeBasicAuth(client.id, client.secret) },
      body: new URLSearchParams({ grant_type: "client_credentials", scope }),
    });
    return { status: response.status, body: await response.json() };
  }

  async function grantsOn(id: string): Promise<
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
    expect(response.status, await response.clone().text()).toStrictEqual(200);
    return (await response.json()).grants;
  }

  it("refuses to register a machine client that states no scope allowlist", async () => {
    await rejection(
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
    expect(both.status, JSON.stringify(both.body)).toStrictEqual(200);
    expect(both.body.scope).toStrictEqual(
      `${ORGANIZATIONS_READ} ${ORGANIZATIONS_WRITE}`,
    );
    const outside = await machineToken("identity:users:read");
    expect(outside.status).toStrictEqual(400);
    expect(outside.body.error).toStrictEqual("invalid_scope");
  });

  it("mints a JWT naming the client as its subject for a machine client that opted in", async () => {
    const issued = await machineToken(ORGANIZATIONS_READ, JWT_REPORTER);
    expect(issued.status, JSON.stringify(issued.body)).toStrictEqual(200);
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
    expect(claims.sub).toStrictEqual(JWT_REPORTER.id);
    expect(claims.client_id).toStrictEqual(JWT_REPORTER.id);
    expect(claims.scope).toStrictEqual(ORGANIZATIONS_READ);
    expect(
      "permissions" in claims,
      "a machine token holds no permissions",
    ).toBeFalsy();
    expect("username" in claims, "a machine token names no person").toBeFalsy();
  });

  it("refuses a machine token an OIDC scope even when its allowlist names one", async () => {
    const oidcListed = { id: "oidc-listed", secret: "oidc-listed-secret" };
    await tenant.addClient({
      ...oidcListed,
      grants: ["client_credentials"],
      scopes: [ORGANIZATIONS_READ, "openid"],
    });
    const refused = await machineToken("openid", oidcListed);
    expect(refused.status, JSON.stringify(refused.body)).toStrictEqual(400);
    expect(refused.body.error).toStrictEqual("invalid_scope");
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
    expect(response.status, JSON.stringify(body)).toStrictEqual(401);
    expect(body.error).toStrictEqual("invalid_client");
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
    expect(response.status).toStrictEqual(200);
    expect(await response.json()).toStrictEqual({ active: false });
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
    expect(listed.map((grant) => grant.roleName)).toStrictEqual([
      "alpha",
      "Zeta",
    ]);
  });

  it("lists a grant of a built-in tier as one, with no role id", async () => {
    tenant.grant({
      resource: { type: "document", id: "doc-5" },
      subject: { type: "user", id: "bob" },
      permissions: ["documents:read"],
      role: "member",
    });
    const [held] = await grantsOn("doc-5");
    expect(held.builtInRole).toStrictEqual("member");
    expect(held.roleId).toStrictEqual(null);
    expect(held.roleSlug).toStrictEqual("member");
    expect(held.roleName).toStrictEqual("Member");
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
    expect(derived.roleSlug).toStrictEqual("documents-read");
    expect(derived.roleName).toStrictEqual("documents-read");
    const [named] = await grantsOn("doc-3");
    expect(named.roleSlug).toStrictEqual("reviewer");
    expect(named.roleName).toStrictEqual("Reviewer");
    const [sameRole] = await grantsOn("doc-4");
    expect(sameRole.roleId).toStrictEqual(named.roleId);
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
    expect(listed.roleId).toStrictEqual(roleId);
    expect(listed.roleName).toStrictEqual("Document reviewer");
  });

  it("advertises its endpoints on the issuer it was given", async () => {
    const metadata = await (
      await fetch(url("/.well-known/oauth-authorization-server"))
    ).json();
    expect(metadata.issuer).toStrictEqual(tenant.issuer);
    expect(metadata.introspection_endpoint).toStrictEqual(
      url("/api/oauth2/introspect"),
    );
    expect(metadata.jwks_uri).toStrictEqual(url("/api/oauth2/jwks"));
  });

  it("adds the organization picked at sign-in, and only that one", async () => {
    const { access_token } = await signIn("ada", "org-acme");
    const claims = await introspect(access_token);
    expect(claims.org_id).toStrictEqual("org-acme");
    expect(claims.org_slug).toStrictEqual("acme");
    expect(claims.org_roles).toStrictEqual(["editor"]);
    expect(claims.permissions?.sort()).toStrictEqual([
      "documents:read",
      "notes:write",
    ]);
  });

  async function authorizeWith(params: Record<string, string>): Promise<URL> {
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
    expect(callback.searchParams.get("error")).toStrictEqual("invalid_request");
    expect(callback.searchParams.has("code")).toBeFalsy();
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
    expect(
      location && new URL(location).searchParams.has("code"),
      `answered ${response.status} ${location}`,
    ).toBeFalsy();
  });

  it("serves UserInfo for the signed-in person", async () => {
    const { access_token } = await signIn("ada");
    const response = await fetch(url("/api/oauth2/userinfo"), {
      headers: { authorization: `Bearer ${access_token}` },
    });
    const claims = await response.json();
    expect(claims.sub).toStrictEqual("ada");
    expect(claims.name).toStrictEqual("Ada Lovelace");
    expect(claims.email).toStrictEqual("ada@example.com");
    expect(claims.email_verified).toStrictEqual(true);
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
    expect(claims.aud).toStrictEqual(MCP);
    expect(claims.org_id).toStrictEqual("org-acme");
    expect(claims.permissions.sort()).toStrictEqual([
      "documents:read",
      "notes:write",
    ]);
  });
});

describe("createFakeTenant's organization and account APIs", () => {
  const DAY_MS = 24 * 60 * 60 * 1000;
  let tenant: FakeTenant;
  let server: TestServer;

  beforeAll(async () => {
    server = await serve((request) => tenant.fetch(request));
    tenant = await createFakeTenant({ issuer: server.origin });
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
    expect(response.status).toStrictEqual(200);
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
    expect(created.status).toStrictEqual(201);
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
    expect(reply.status).toStrictEqual(200);
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
      expect(reply.body.memberships.map((entry) => entry.roles)).toStrictEqual([
        ["member"],
      ]);
    }
  });

  it("starts a login session for every sign-in, so each browser is a device of its own", async () => {
    const person = await addPerson();
    tenant.signInAs(person);
    const first = await authorize(APP, {});
    const second = await authorize(APP, {});
    const third = await authorize();
    const listed = await sessionsOf(third);
    expect(listed.length).toStrictEqual(3);
    for (const token of [first, second, third]) {
      expect(
        (await call(token, "GET", "/api/account")).status,
        "a sign-in in another browser revoked this one's credential",
      ).toStrictEqual(200);
    }
    const currents = await Promise.all(
      [first, second, third].map(
        async (token) =>
          (await sessionsOf(token)).find((session) => session.current)?.id,
      ),
    );
    expect(new Set(currents).size).toStrictEqual(3);
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
    expect(adaSessions.length).toStrictEqual(1);
    expect(
      (await call(adaFirst, "GET", "/api/account")).status,
      "the same browser signed in again and left its earlier credential live",
    ).toStrictEqual(401);

    tenant.signInAs(bob);
    const asBob = await authorize(APP, browser);
    expect((await sessionsOf(asBob)).length).toStrictEqual(1);
    expect(
      (await sessionsOf(adaAgain)).map((session) => session.id),
      "another person's sign-in in this browser ended or joined ada's session",
    ).toStrictEqual(adaSessions.map((session) => session.id));

    tenant.signInAs(ada);
    const adaReturns = await authorize(APP, browser);
    const returned = await sessionsOf(adaReturns);
    expect(returned.length).toStrictEqual(2);
    expect(
      returned.find((session) => session.current)?.id === adaSessions[0].id,
      "a cookie naming bob's session continued ada's",
    ).toBeFalsy();
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
    expect(revoked.status).toStrictEqual(204);
    const again = await authorize(APP, browser);
    const listed = await sessionsOf(again);
    expect(listed.length).toStrictEqual(2);
    expect(
      listed.some((session) => session.id === endedSession.id),
    ).toBeFalsy();
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
    expect(
      onHttps.headers.get("set-cookie")?.split("; ").slice(1),
    ).toStrictEqual(["Path=/", "HttpOnly", "SameSite=Lax", "Secure"]);
    expect(
      onHttp.headers.get("set-cookie")?.split("; ").slice(1),
    ).toStrictEqual(["Path=/", "HttpOnly", "SameSite=Lax"]);
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
    expect(listed.map((session) => session.userAgent)).toStrictEqual([
      "Laptop Browser",
      "Phone Browser",
    ]);
    expect(listed.map((session) => session.ipAddress)).toStrictEqual([
      null,
      "192.0.2.10",
    ]);
    expect(
      (await sessionsOf(againOnPhone)).find((session) => session.current)?.id,
    ).toStrictEqual(listed[1].id);
    const replaced = await call(onPhone, "GET", "/api/account/sessions");
    expect(
      replaced.status,
      "a second sign-in in the same browser left the first credential live",
    ).toStrictEqual(401);
  });

  async function revoke(token: string, client = APP): Promise<void> {
    const response = await fetch(url("/api/oauth2/revoke"), {
      method: "POST",
      headers: { authorization: encodeBasicAuth(client.id, client.secret) },
      body: new URLSearchParams({ token }),
    });
    await response.body?.cancel();
    expect(response.status).toStrictEqual(200);
  }

  it("keeps a third-party app's credentials apart from the login session they came from", async () => {
    const person = await addPerson();
    const phoneBrowser: Browser = {};
    tenant.signInAs(person, { userAgent: "Phone Browser" });
    const firstParty = await authorize(APP, phoneBrowser);
    const thirdParty = await authorize(PARTNER, phoneBrowser);
    const [phone] = await sessionsOf(firstParty);
    expect(
      (await sessionsOf(thirdParty)).find((session) => session.current)?.id,
      "a third-party credential names the session it came from as current",
    ).toStrictEqual(phone.id);
    const firstPartyAgain = await authorize(APP, phoneBrowser);
    expect(
      (await call(firstParty, "GET", "/api/account")).status,
      "a first-party sign-in in the same browser left its predecessor live",
    ).toStrictEqual(401);
    expect(
      (await call(thirdParty, "GET", "/api/account")).status,
      "a first-party sign-in revoked a third-party credential",
    ).toStrictEqual(200);

    await revoke(thirdParty, PARTNER);
    expect(
      (await sessionsOf(firstPartyAgain)).map((session) => session.id),
      "revoking a third-party credential ended the login session",
    ).toStrictEqual([phone.id]);

    const partnerAgain = await authorize(PARTNER, phoneBrowser);
    tenant.signInAs(person, { userAgent: "Laptop Browser" });
    const onLaptop = await authorize();
    const ended = await call(
      onLaptop,
      "DELETE",
      `/api/account/sessions/${phone.id}`,
    );
    expect(ended.status).toStrictEqual(204);
    expect(
      (await call(firstPartyAgain, "GET", "/api/account")).status,
    ).toStrictEqual(401);
    expect(
      (await call(partnerAgain, "GET", "/api/account")).status,
      "ending the login session revoked a third-party credential",
    ).toStrictEqual(200);
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
    expect(refreshed.ok, "another app refreshed this app's token").toBeFalsy();
    expect((await sessionsOf(issued.access_token)).length).toStrictEqual(1);
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
    expect(rotated.status).toStrictEqual(200);
    const successor = await rotated.json();
    expect((await sessionsOf(onLaptop)).length).toStrictEqual(2);

    const replayed = await fetch(url("/api/oauth2/token"), {
      method: "POST",
      headers: { authorization: encodeBasicAuth(APP.id, APP.secret) },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: issued.refresh_token!,
      }),
    });
    await replayed.body?.cancel();
    expect(replayed.status).toStrictEqual(400);
    expect(
      (await call(successor.access_token, "GET", "/api/account")).status,
    ).toStrictEqual(401);
    expect(
      (await sessionsOf(onLaptop)).map((session) => session.userAgent),
      "a revoked family left its login session listed",
    ).toStrictEqual(["Laptop Browser"]);
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
    expect(ended.status).toStrictEqual(204);

    tenant.signInAs(person, { userAgent: "Phone Browser" });
    const listed = await sessionsOf(await authorize());
    expect(listed.length).toStrictEqual(2);
    expect(
      listed.some((session) => session.id === phoneSession.id),
    ).toBeFalsy();
  });

  it("gives a minted access token no login session, so it cannot sign out the others", async () => {
    const person = await addPerson();
    tenant.signInAs(person);
    await authorize();
    const minted = await mint(person);
    const listed = await sessionsOf(minted);
    expect(listed.map((session) => session.current)).toStrictEqual([false]);
    const refused = await call<{ reason?: string }>(
      minted,
      "POST",
      "/api/account/sessions/revoke-others",
    );
    expect(refused.status).toStrictEqual(409);
    expect(refused.body.reason).toStrictEqual("current_session_required");
  });

  it("answers the metadata bucket a person was seeded with", async () => {
    const person = await addPerson({ userMetadata: { plan: "trial" } });
    const reply = await call(await mint(person), "GET", "/api/account");
    expect(reply.body).toStrictEqual({ userMetadata: { plan: "trial" } });
  });

  it("refuses a metadata bucket larger than sixteen kilobytes", async () => {
    const person = await addPerson();
    const reply = await call(await mint(person), "PATCH", "/api/account", {
      userMetadata: { notes: "x".repeat(16 * 1024) },
    });
    expect(reply.status).toStrictEqual(400);
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
      roles.body.some(
        (role) => role.slug === "reviewer" && role.name === "Reviewer",
      ),
    );
    const offered = await call(
      ownerToken,
      "POST",
      `/api/organizations/${organizationId}/invitations`,
      { email: `${invitee}@example.com`, role: "reviewer" },
    );
    expect(offered.status).toStrictEqual(201);
    const waiting = await call<{ offers: { roleName: string }[] }>(
      await mint(invitee),
      "GET",
      "/api/organizations/offers",
    );
    expect(waiting.body.offers.map((offer) => offer.roleName)).toStrictEqual([
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
    expect(first.body.data.length).toStrictEqual(20);
    expect(first.body.hasMore).toStrictEqual(true);
    expect(first.body.cursors.prev).toStrictEqual(null);
    const second = await pageAt(first.body.cursors.next);
    expect(second.body.data.length).toStrictEqual(5);
    expect(second.body.hasMore).toStrictEqual(false);
    expect(
      [...first.body.data, ...second.body.data].map((row) => row.userId).sort(),
    ).toStrictEqual([...people].sort());
    const back = await pageAt(second.body.cursors.prev);
    expect(back.body.data).toStrictEqual(first.body.data);
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
    expect(deleted.status).toStrictEqual(204);
    const inviteeToken = await mint(invitee);
    const waiting = await call<{ offers: unknown[] }>(
      inviteeToken,
      "GET",
      "/api/organizations/offers",
    );
    expect(waiting.body.offers).toStrictEqual([]);
    const accepted = await call<{ status: string }>(
      inviteeToken,
      "POST",
      `/api/organizations/offers/${offered.body.membership.id}/accept`,
    );
    expect(accepted.body.status).toStrictEqual("invalid");
  });

  it("stores a return_to on a registered origin or on the tenant's own host", async () => {
    const ownerToken = await mint(await addPerson());
    const organizationId = await createOrganization(ownerToken, "Returning");
    for (const returnTo of [
      `${new URL(REDIRECT).origin}/welcome`,
      "/organization-invite",
    ]) {
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
      expect(offered.status).toStrictEqual(201);
      expect(offered.body.invitation.returnTo).toStrictEqual(returnTo);
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
    expect(reply.status).toStrictEqual(400);
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
    expect(
      waiting.body.offers,
      "an expired invitation was offered",
    ).toStrictEqual([]);
    const accepted = await call<{ status: string }>(
      holderToken,
      "POST",
      `/api/organizations/offers/${offered.body.invitation.id}/accept`,
    );
    expect(accepted.body.status).toStrictEqual("expired");
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
    expect(reply.status).toStrictEqual(200);
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
    expect(granted.status, JSON.stringify(granted.body)).toStrictEqual(201);
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
    expect(await permitted(memberToken, permission)).toBeFalsy();

    expect(
      tenant.defineOrganizationRole({ slug, permissions: [permission] }),
    ).toStrictEqual(roleId);
    assert(
      await permitted(memberToken, permission),
      "a holder kept the role's earlier permissions",
    );
    const roles = await call<{ id?: string; slug: string; name: string }[]>(
      await mint(owner),
      "GET",
      `/api/organizations/${organizationId}/member-roles`,
    );
    expect(roles.body.filter((role) => role.slug === slug)).toStrictEqual([
      { id: roleId, slug, name: slug },
    ]);
  });

  it("defines a role under the id it is given, and refuses an id another role holds or a new id for a defined slug", () => {
    const id = crypto.randomUUID();
    expect(
      tenant.defineOrganizationRole({ slug: `given-${id}`, id }),
    ).toStrictEqual(id);
    thrown(
      () =>
        tenant.defineOrganizationRole({
          slug: `given-${id}`,
          id: crypto.randomUUID(),
        }),
      Error,
      id,
    );
    thrown(
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
    expect(await permitted(await mint(member, there), permission)).toBeFalsy();
    expect(await permitted(await mint(member), permission)).toBeFalsy();
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
    expect(
      await permitted(await mint(member, organizationId), permission),
      "a role outlived the membership removeMember ended",
    ).toBeFalsy();
    const held = await call<unknown[]>(
      ownerToken,
      "GET",
      `/api/organizations/${organizationId}/members/${member}/roles`,
    );
    expect(held.body).toStrictEqual([]);
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
    expect(revoked.status).toStrictEqual(204);
    const offered = await call<{ membership: { id: string } }>(
      ownerToken,
      "POST",
      `/api/organizations/${organizationId}/invitations`,
      { email: `${member}@example.com`, role: "member" },
    );
    expect(offered.status).toStrictEqual(201);
    const memberToken = await mint(member);
    const accepted = await call<{ status: string }>(
      memberToken,
      "POST",
      `/api/organizations/offers/${offered.body.membership.id}/accept`,
    );
    expect(accepted.body.status).toStrictEqual("accepted");
    expect(
      await permitted(await mint(member, organizationId), permission),
      "rejoining restored what the ended membership was seeded with",
    ).toBeFalsy();
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
    expect(deleted.status).toStrictEqual(204);
    tenant.addOrganization({ id: organizationId, slug: `sealed-${owner}` });
    tenant.addMember(organizationId, owner);
    expect(
      await permitted(await mint(owner, organizationId), permission),
      "a deleted organization's role came back with an organization of its id",
    ).toBeFalsy();
  });
});
