import { assert, expect, it } from "vitest";
import { encodeBasicAuth } from "../utils/basic-auth.ts";
import { generateCodeChallenge, generateCodeVerifier } from "../utils/pkce.ts";
import { createFakeTenant } from "./tenant.ts";

it("concurrent exchanges keep each browser's session binding", async () => {
  const issuer = "https://identity.example.com";
  const tenant = await createFakeTenant({ issuer });
  const client = { id: "app", secret: "app-secret" };
  const redirectUri = "https://app.example.com/auth/callback";
  await tenant.addClient({ ...client, redirectUris: [redirectUri] });
  await tenant.addUser({ id: "person", username: "person" });
  tenant.addOrganization({ id: "org", slug: "org" });
  tenant.addMember("org", "person");
  const request = (path: string, init: RequestInit = {}) =>
    tenant.fetch(new Request(issuer + path, init));
  const credentialHeaders = {
    authorization: encodeBasicAuth(client.id, client.secret),
  };

  async function codeFor(device: string): Promise<Record<string, string>> {
    tenant.signInAs("person", { organizationId: "org", userAgent: device });
    const verifier = generateCodeVerifier();
    const params = new URLSearchParams({
      response_type: "code",
      client_id: client.id,
      redirect_uri: redirectUri,
      scope: "openid offline_access",
      state: device,
      code_challenge: await generateCodeChallenge(verifier),
      code_challenge_method: "S256",
    });
    const response = await request(`/api/oauth2/authorize?${params}`);
    await response.body?.cancel();
    const code = new URL(response.headers.get("location")!).searchParams.get(
      "code",
    );
    assert(code);
    return {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    };
  }

  async function exchange(body: Record<string, string>): Promise<string> {
    const response = await request("/api/oauth2/token", {
      method: "POST",
      headers: credentialHeaders,
      body: new URLSearchParams(body),
    });
    expect(response.status).toStrictEqual(200);
    return (await response.json()).access_token;
  }

  async function active(token: string): Promise<boolean> {
    const response = await request("/api/oauth2/introspect", {
      method: "POST",
      headers: credentialHeaders,
      body: new URLSearchParams({ token }),
    });
    return (await response.json()).active;
  }

  async function currentSession(
    token: string,
  ): Promise<{ id: string; userAgent: string }> {
    const response = await request("/api/account/sessions", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(response.status).toStrictEqual(200);
    const body = await response.json();
    const current = body.sessions.filter(
      (session: { current: boolean }) => session.current,
    );
    expect(current.length).toStrictEqual(1);
    return current[0];
  }

  const phoneCode = await codeFor("phone");
  const laptopCode = await codeFor("laptop");
  const [phone, laptop] = await Promise.all([
    exchange(phoneCode),
    exchange(laptopCode),
  ]);
  expect(
    await active(phone),
    "the phone credential must remain active",
  ).toStrictEqual(true);
  expect(
    await active(laptop),
    "the laptop credential must remain active",
  ).toStrictEqual(true);
  const phoneSession = await currentSession(phone);
  const laptopSession = await currentSession(laptop);
  expect(phoneSession.userAgent).toStrictEqual("phone");
  expect(laptopSession.userAgent).toStrictEqual("laptop");
  assert(phoneSession.id !== laptopSession.id);
  const revoked = await request(`/api/account/sessions/${phoneSession.id}`, {
    method: "DELETE",
    headers: { authorization: `Bearer ${laptop}` },
  });
  await revoked.body?.cancel();
  expect(revoked.status).toStrictEqual(204);
  expect(await active(phone)).toStrictEqual(false);
  expect(await active(laptop)).toStrictEqual(true);
});
