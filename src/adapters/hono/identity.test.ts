import { describe, expect, it } from "vitest";
import { Hono } from "hono";

import type { DeliveryMessage } from "../../identity/delivery.ts";
import { IdentityError } from "../../identity/errors.ts";
import type { PasswordCredential } from "../../identity/password.ts";
import type { PasswordPolicy } from "../../identity/password-policy.ts";
import {
  MemoryTokenFlowStore,
  TokenFlowService,
} from "../../identity/token-flow.ts";
import {
  IdentityService,
  type IdentityUserStore,
} from "../../identity/service.ts";

import {
  type HonoIdentityCsrfOptions,
  honoIdentityRoutes,
} from "./identity.ts";

interface TestUser {
  id: string;
  email?: string;
}

function build(
  withAuthHook = true,
  passwordPolicy?: PasswordPolicy,
  csrf?: HonoIdentityCsrfOptions | false,
) {
  const byId = new Map<string, TestUser>();
  const emailToId = new Map<string, string>();
  const creds = new Map<string, PasswordCredential>();
  let seq = 0;
  const profiles: Record<string, unknown>[] = [];
  const verifiedCalls: { userId: string; email?: string }[] = [];
  const store: IdentityUserStore<TestUser> = {
    create(profile, credential) {
      const id = `u${++seq}`;
      profiles.push(profile);
      const user: TestUser = { id, email: profile.email as string | undefined };
      byId.set(id, user);
      if (user.email) emailToId.set(user.email, id);
      creds.set(id, credential);
      return Promise.resolve(user);
    },
    findByIdentifier(identifier) {
      const id = emailToId.get(identifier);
      return Promise.resolve(id ? byId.get(id) : undefined);
    },
    findByEmail(email) {
      const id = emailToId.get(email);
      return Promise.resolve(id ? byId.get(id) : undefined);
    },
    getCredential(userId) {
      return Promise.resolve(creds.get(userId));
    },
    setCredential(userId, credential) {
      creds.set(userId, credential);
      return Promise.resolve();
    },
    markEmailVerified(userId, email) {
      verifiedCalls.push({ userId, email });
      return Promise.resolve();
    },
  };

  const sent: DeliveryMessage[] = [];
  const service = new IdentityService<TestUser>({
    users: store,
    tokens: new TokenFlowService(new MemoryTokenFlowStore()),
    passwordPolicy,
    delivery: {
      sendPasswordReset: (m) => {
        sent.push(m);
      },
      sendEmailVerification: (m) => {
        sent.push(m);
      },
    },
  });

  const app = new Hono();
  app.route(
    "/auth",
    honoIdentityRoutes(service, {
      onAuthenticated: withAuthHook
        ? (c, user, action) => c.json({ action, userId: user.id })
        : undefined,
      csrf,
    }),
  );
  return { app, service, sent, profiles, verifiedCalls };
}

function postJson(
  app: Hono,
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
) {
  return app.request(`http://localhost${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

function postForm(
  app: Hono,
  path: string,
  body: Record<string, string>,
  headers: Record<string, string> = {},
) {
  return app.request(`http://localhost${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: new URLSearchParams(body),
  });
}

describe("honoIdentityRoutes", () => {
  it("signup → onAuthenticated, signin verifies (200 / 401)", async () => {
    const { app } = build();
    const signup = await postJson(app, "/auth/signup", {
      password: "hunter2hunter2",
      email: "a@b.co",
    });
    expect(signup.status).toStrictEqual(200);
    expect((await signup.json()).action).toStrictEqual("signUp");

    const ok = await postJson(app, "/auth/signin", {
      identifier: "a@b.co",
      password: "hunter2hunter2",
    });
    expect(ok.status).toStrictEqual(200);
    expect((await ok.json()).action).toStrictEqual("signIn");

    const bad = await postJson(app, "/auth/signin", {
      identifier: "a@b.co",
      password: "wrong",
    });
    expect(bad.status).toStrictEqual(401);
    await bad.body?.cancel();
  });

  it("password reset request is always ok; reset consumes the token", async () => {
    const { app, sent } = build();
    await postJson(app, "/auth/signup", {
      password: "oldpassword1",
      email: "a@b.co",
    });

    const unknown = await postJson(app, "/auth/password/reset-request", {
      email: "ghost@b.co",
    });
    expect(unknown.status).toStrictEqual(200);
    expect(sent.length).toStrictEqual(0);

    const known = await postJson(app, "/auth/password/reset-request", {
      email: "a@b.co",
    });
    expect(known.status).toStrictEqual(200);
    expect(sent.length).toStrictEqual(1);

    const token = sent[0].token;
    const reset = await postJson(app, "/auth/password/reset", {
      token,
      password: "newpassword1",
    });
    expect(reset.status).toStrictEqual(200);

    const ok = await postJson(app, "/auth/signin", {
      identifier: "a@b.co",
      password: "newpassword1",
    });
    expect(ok.status).toStrictEqual(200);
    await ok.body?.cancel();

    const replay = await postJson(app, "/auth/password/reset", {
      token,
      password: "again12345",
    });
    expect(replay.status).toStrictEqual(400);
    await replay.body?.cancel();
  });

  it("email verify consumes a valid token, rejects a bad one", async () => {
    const { app, service, sent } = build();
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    await service.requestEmailVerification({
      userId: user.id,
      email: "a@b.co",
    });
    const token = sent[0].token;

    const ok = await postJson(app, "/auth/email/verify", { token });
    expect(ok.status).toStrictEqual(200);
    expect((await ok.json()).userId).toStrictEqual(user.id);

    const bad = await postJson(app, "/auth/email/verify", { token: "nope" });
    expect(bad.status).toStrictEqual(400);
    await bad.body?.cancel();
  });

  it("hands the store the address the verification token was issued for", async () => {
    const { app, service, sent, verifiedCalls } = build();
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    await service.requestEmailVerification({
      userId: user.id,
      email: "a@b.co",
    });

    const res = await postJson(app, "/auth/email/verify", {
      token: sent[0].token,
    });
    expect(res.status).toStrictEqual(200);
    await res.body?.cancel();

    expect(verifiedCalls).toStrictEqual([{ userId: user.id, email: "a@b.co" }]);
  });

  it("accepts form-encoded bodies too", async () => {
    const { app } = build();
    const res = await postForm(app, "/auth/signup", {
      password: "hunter2hunter2",
      email: "f@b.co",
    });
    expect(res.status).toStrictEqual(200);
    await res.body?.cancel();
  });

  it("maps a thrown IdentityError to the stable { error: code } response", async () => {
    const store: IdentityUserStore<TestUser> = {
      create() {
        return Promise.reject(new IdentityError("identifier_taken"));
      },
      findByIdentifier: () => Promise.resolve(undefined),
      findByEmail: () => Promise.resolve(undefined),
      getCredential: () => Promise.resolve(undefined),
      setCredential: () => Promise.resolve(),
    };
    const service = new IdentityService<TestUser>({
      users: store,
      tokens: new TokenFlowService(new MemoryTokenFlowStore()),
    });
    const app = new Hono();
    app.route(
      "/auth",
      honoIdentityRoutes(service, {
        onAuthenticated: (c) => c.json({ ok: 1 }),
      }),
    );

    const res = await postJson(app, "/auth/signup", {
      password: "hunter2hunter2",
      email: "dupe@b.co",
    });
    expect(res.status).toStrictEqual(409);
    expect((await res.json()).error).toStrictEqual("identifier_taken");
  });

  it("coerces a numeric JSON password so the length policy applies to it", async () => {
    const { app } = build(true, {});
    const res = await postJson(app, "/auth/signup", {
      password: 12345,
      email: "n@b.co",
    });
    expect(res.status).toStrictEqual(422);
    expect((await res.json()).error).toStrictEqual("weak_password");

    const signin = await postJson(app, "/auth/signin", {
      identifier: "n@b.co",
      password: "12345",
    });
    expect(signin.status).toStrictEqual(401);
    await signin.body?.cancel();
  });

  it("hands the policy the same string the credential is hashed from", async () => {
    const seen: unknown[] = [];
    const { app } = build(true, {
      validators: [
        (password) => {
          seen.push(password);
          return undefined;
        },
      ],
    });
    const res = await postJson(app, "/auth/signup", {
      password: { length: 12 },
      email: "o@b.co",
    });
    expect(res.status).toStrictEqual(200);
    await res.body?.cancel();

    expect(seen.length).toStrictEqual(1);
    expect(typeof seen[0]).toStrictEqual("string");
    expect(seen[0]).toStrictEqual(String({ length: 12 }));

    const signin = await postJson(app, "/auth/signin", {
      identifier: "o@b.co",
      password: seen[0],
    });
    expect(signin.status).toStrictEqual(200);
    await signin.body?.cancel();
  });

  it("rejects an array password by its coerced length, before it reaches the hash", async () => {
    const { app } = build(true, {});
    const res = await postJson(app, "/auth/signup", {
      password: Array.from({ length: 10 }, () => "a".repeat(100_000)),
      email: "arr@b.co",
    });
    expect(res.status).toStrictEqual(422);
    expect((await res.json()).error).toStrictEqual("weak_password");

    const signin = await postJson(app, "/auth/signin", {
      identifier: "arr@b.co",
      password: "whatever",
    });
    expect(signin.status).toStrictEqual(401);
    await signin.body?.cancel();
  });

  it("leaves profile fields at their JSON types instead of flattening them", async () => {
    const { app, profiles } = build(true, {});
    const res = await postJson(app, "/auth/signup", {
      password: "hunter2hunter2",
      email: "p@b.co",
      emailVerified: false,
      age: 41,
      nickname: null,
      address: { city: "Portland" },
      tags: ["a", "b"],
    });
    expect(res.status).toStrictEqual(200);
    await res.body?.cancel();

    expect(profiles.length).toStrictEqual(1);
    expect(profiles[0]).toStrictEqual({
      email: "p@b.co",
      emailVerified: false,
      age: 41,
      nickname: null,
      address: { city: "Portland" },
      tags: ["a", "b"],
    });
  });

  it("ignores a JSON body that is not an object", async () => {
    const { app } = build(true, {});
    for (const body of [["password"], "password", 42, null]) {
      const res = await postJson(app, "/auth/signup", body);
      expect(res.status).toStrictEqual(400);
      expect((await res.json()).error).toStrictEqual("invalid_request");
    }
  });

  it("does not mount signup/signin without an onAuthenticated hook", async () => {
    const { app } = build(false);
    const signup = await postJson(app, "/auth/signup", { password: "x" });
    expect(signup.status).toStrictEqual(404);
    await signup.body?.cancel();
    const signin = await postJson(app, "/auth/signin", { identifier: "a" });
    expect(signin.status).toStrictEqual(404);
    await signin.body?.cancel();
    const reset = await postJson(app, "/auth/password/reset-request", {
      email: "x@y.co",
    });
    expect(reset.status).toStrictEqual(200);
  });
});

describe("honoIdentityRoutes cross-site protection", () => {
  const credentials = { password: "hunter2hunter2", email: "c@b.co" };

  it("refuses a form POST the browser reports as cross-site", async () => {
    const { app } = build();
    const res = await postForm(app, "/auth/signup", credentials, {
      origin: "https://evil.example",
      "sec-fetch-site": "cross-site",
    });
    expect(res.status).toStrictEqual(403);
    expect((await res.json()).error).toStrictEqual("forbidden_origin");
  });

  it("refuses a request from a sibling site of the same registrable domain", async () => {
    const { app } = build();
    const res = await postJson(app, "/auth/signin", credentials, {
      origin: "https://other.localhost",
      "sec-fetch-site": "same-site",
    });
    expect(res.status).toStrictEqual(403);
    expect((await res.json()).error).toStrictEqual("forbidden_origin");
  });

  it("accepts a request the browser reports as same-origin", async () => {
    const { app } = build();
    const res = await postForm(app, "/auth/signup", credentials, {
      origin: "http://localhost",
      "sec-fetch-site": "same-origin",
    });
    expect(res.status).toStrictEqual(200);
    await res.body?.cancel();
  });

  it("accepts a directly navigated request, which carries no other site", async () => {
    const { app } = build();
    const res = await postForm(
      app,
      "/auth/password/reset-request",
      {
        email: "c@b.co",
      },
      { "sec-fetch-site": "none" },
    );
    expect(res.status).toStrictEqual(200);
    await res.body?.cancel();
  });

  it("accepts a caller that sends neither header, since forgery needs a browser", async () => {
    const { app } = build();
    const res = await postJson(app, "/auth/signup", credentials);
    expect(res.status).toStrictEqual(200);
    await res.body?.cancel();
  });

  it("falls back to the Origin host, not its scheme, when the browser sends no Sec-Fetch-Site", async () => {
    const { app } = build();
    const refused = await postForm(app, "/auth/signup", credentials, {
      origin: "https://evil.example",
    });
    expect(refused.status).toStrictEqual(403);
    expect((await refused.json()).error).toStrictEqual("forbidden_origin");

    const accepted = await postForm(app, "/auth/signup", credentials, {
      origin: "https://localhost",
    });
    expect(accepted.status).toStrictEqual(200);
    await accepted.body?.cancel();
  });

  it("refuses an opaque origin", async () => {
    const { app } = build();
    const res = await postForm(app, "/auth/signup", credentials, {
      origin: "null",
    });
    expect(res.status).toStrictEqual(403);
    await res.body?.cancel();
  });

  it("accepts an origin the caller allow-listed", async () => {
    const { app } = build(true, undefined, {
      allowedOrigins: ["https://app.example"],
    });
    const res = await postForm(app, "/auth/signup", credentials, {
      origin: "https://app.example",
      "sec-fetch-site": "cross-site",
    });
    expect(res.status).toStrictEqual(200);
    await res.body?.cancel();
  });

  it("mounts no guard at all when csrf is false", async () => {
    const { app } = build(true, undefined, false);
    const res = await postForm(app, "/auth/signup", credentials, {
      origin: "https://evil.example",
      "sec-fetch-site": "cross-site",
    });
    expect(res.status).toStrictEqual(200);
    await res.body?.cancel();
  });

  it("leaves safe methods to the router, so a cross-site GET still 404s", async () => {
    const { app } = build();
    const res = await app.request("http://localhost/auth/signup", {
      headers: { "sec-fetch-site": "cross-site" },
    });
    expect(res.status).toStrictEqual(404);
    await res.body?.cancel();
  });
});
